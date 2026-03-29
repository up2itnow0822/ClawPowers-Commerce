/**
 * Shared test helpers for @clawpowers/guard tests.
 */
import {
  generateEd25519KeyPair,
  signAgentJWT,
  _clearNonceCache,
} from '@clawpowers/core';
import type { AgentIdentityPayload } from '@clawpowers/core';

export async function makeKeyPair(): Promise<CryptoKeyPair> {
  return generateEd25519KeyPair();
}

export function makePayload(
  overrides: Partial<AgentIdentityPayload> = {},
): AgentIdentityPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: 'https://issuer.example.com',
    sub: 'agent:test-001',
    iat: now,
    exp: now + 3600,
    nonce: crypto.randomUUID(),
    operatorId: 'openai',
    operatorDomain: 'openai.com',
    agentId: 'gpt-agent-001',
    agentVersion: '1.0.0',
    capabilities: ['browse', 'extract'],
    intent: 'read',
    ...overrides,
  };
}

export async function makeToken(
  payload: AgentIdentityPayload,
  privateKey: CryptoKey,
  kid?: string,
): Promise<string> {
  return signAgentJWT(payload, privateKey, kid);
}

export function clearNonces(): void {
  _clearNonceCache();
}

/** Export raw base64url public key string for GuardConfig */
export async function exportPublicKeyBase64(publicKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  const bytes = new Uint8Array(raw);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
