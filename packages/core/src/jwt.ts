// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ClawPowers Commerce. All Rights Reserved.
// See LICENSE in the repository root for license information.

/**
 * JWT validation using native Web Crypto API (zero dependencies).
 * Supports EdDSA (Ed25519) signed tokens.
 */

import type { AgentIdentityPayload } from './types.js';

/** In-process nonce cache to prevent replay attacks (process-scoped) */
const usedNonces = new Set<string>();

/** Max nonces to keep in memory (evict oldest when exceeded) */
const MAX_NONCES = 10_000;

function base64UrlDecode(str: string): Uint8Array {
  // Pad to multiple of 4
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlDecodeToString(str: string): string {
  const bytes = base64UrlDecode(str);
  return new TextDecoder().decode(bytes);
}

interface JWTHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

/** Errors thrown by JWT validation */
export class JWTValidationError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'JWTValidationError';
  }
}

function assertString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new JWTValidationError(
      `Missing or invalid field: ${field}`,
      'MISSING_FIELD',
    );
  }
  return value;
}

function assertNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new JWTValidationError(
      `Missing or invalid numeric field: ${field}`,
      'MISSING_FIELD',
    );
  }
  return value;
}

function assertStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) {
    throw new JWTValidationError(
      `Field ${field} must be a string array`,
      'INVALID_FIELD',
    );
  }
  return value as string[];
}

/**
 * Validate an agent JWT token.
 *
 * @param token  Raw JWT string (header.payload.signature)
 * @param publicKeys  Map of key ID → CryptoKey (Ed25519 public keys)
 * @returns Parsed and validated AgentIdentityPayload
 * @throws JWTValidationError on any validation failure
 */
export async function validateAgentJWT(
  token: string,
  publicKeys: Map<string, CryptoKey>,
): Promise<AgentIdentityPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JWTValidationError('JWT must have 3 parts', 'MALFORMED_JWT');
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // --- Parse header ---
  let header: JWTHeader;
  try {
    header = JSON.parse(base64UrlDecodeToString(headerB64)) as JWTHeader;
  } catch {
    throw new JWTValidationError('Failed to parse JWT header', 'MALFORMED_JWT');
  }

  if (header.alg !== 'EdDSA') {
    throw new JWTValidationError(
      `Unsupported algorithm: ${header.alg}. Only EdDSA is supported.`,
      'UNSUPPORTED_ALGORITHM',
    );
  }

  // --- Select public key ---
  const kid = header.kid ?? '__default__';
  const publicKey = publicKeys.get(kid) ?? publicKeys.get('__default__');
  if (!publicKey) {
    throw new JWTValidationError(
      `No public key found for kid: ${kid}`,
      'KEY_NOT_FOUND',
    );
  }

  // --- Verify signature ---
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecode(signatureB64);

  let valid: boolean;
  try {
    valid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      signature.buffer as ArrayBuffer,
      signingInput.buffer as ArrayBuffer,
    );
  } catch {
    throw new JWTValidationError(
      'Signature verification failed',
      'INVALID_SIGNATURE',
    );
  }

  if (!valid) {
    throw new JWTValidationError('Invalid signature', 'INVALID_SIGNATURE');
  }

  // --- Parse payload ---
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(base64UrlDecodeToString(payloadB64)) as Record<
      string,
      unknown
    >;
  } catch {
    throw new JWTValidationError(
      'Failed to parse JWT payload',
      'MALFORMED_JWT',
    );
  }

  // --- Validate expiration ---
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = assertNumber(raw['exp'], 'exp');
  if (exp < nowSec) {
    throw new JWTValidationError('Token has expired', 'EXPIRED');
  }

  const iat = assertNumber(raw['iat'], 'iat');
  if (iat > nowSec + 30) {
    // Allow 30s clock skew
    throw new JWTValidationError(
      'Token issued in the future',
      'INVALID_IAT',
    );
  }

  // --- Validate required fields ---
  const iss = assertString(raw['iss'], 'iss');
  const sub = assertString(raw['sub'], 'sub');
  const nonce = assertString(raw['nonce'], 'nonce');
  const operatorId = assertString(raw['operatorId'], 'operatorId');
  const operatorDomain = assertString(raw['operatorDomain'], 'operatorDomain');
  const agentId = assertString(raw['agentId'], 'agentId');
  const agentVersion = assertString(raw['agentVersion'], 'agentVersion');
  const capabilities = assertStringArray(raw['capabilities'], 'capabilities');
  const intent = assertString(raw['intent'], 'intent');

  // --- Validate nonce uniqueness ---
  if (usedNonces.has(nonce)) {
    throw new JWTValidationError('Nonce has already been used', 'REPLAY_ATTACK');
  }
  // Evict oldest nonces if limit reached
  if (usedNonces.size >= MAX_NONCES) {
    const first = usedNonces.values().next().value;
    if (first !== undefined) {
      usedNonces.delete(first);
    }
  }
  usedNonces.add(nonce);

  // --- Validate enum values ---
  const validCapabilities = new Set([
    'browse',
    'interact',
    'extract',
    'transact',
    'subscribe',
  ]);
  for (const cap of capabilities) {
    if (!validCapabilities.has(cap)) {
      throw new JWTValidationError(
        `Unknown capability: ${cap}`,
        'INVALID_FIELD',
      );
    }
  }

  const validIntents = new Set(['read', 'write', 'purchase', 'subscribe']);
  if (!validIntents.has(intent)) {
    throw new JWTValidationError(`Unknown intent: ${intent}`, 'INVALID_FIELD');
  }

  const payload: AgentIdentityPayload = {
    iss,
    sub,
    iat,
    exp,
    nonce,
    operatorId,
    operatorDomain,
    agentId,
    agentVersion,
    capabilities: capabilities as AgentIdentityPayload['capabilities'],
    intent: intent as AgentIdentityPayload['intent'],
  };

  if (typeof raw['walletAddress'] === 'string') {
    payload.walletAddress = raw['walletAddress'];
  }
  if (typeof raw['walletChain'] === 'string') {
    payload.walletChain = raw['walletChain'];
  }

  return payload;
}

/** Clear the nonce cache (for testing only) */
export function _clearNonceCache(): void {
  usedNonces.clear();
}

/**
 * Import an Ed25519 public key from raw bytes (32 bytes).
 */
export async function importEd25519PublicKey(
  rawBytes: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    rawBytes.buffer as ArrayBuffer,
    { name: 'Ed25519' },
    true,
    ['verify'],
  );
}

/**
 * Generate an Ed25519 key pair (for testing).
 */
export async function generateEd25519KeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  );
}

/**
 * Sign a JWT payload with an Ed25519 private key (for testing/issuance).
 */
export async function signAgentJWT(
  payload: AgentIdentityPayload,
  privateKey: CryptoKey,
  kid?: string,
): Promise<string> {
  const header: JWTHeader = { alg: 'EdDSA', typ: 'JWT' };
  if (kid) header.kid = kid;

  const encode = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

  const headerB64 = encode(header);
  const payloadB64 = encode(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    signingInput,
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return `${headerB64}.${payloadB64}.${sigB64}`;
}
