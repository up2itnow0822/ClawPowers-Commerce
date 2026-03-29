import { describe, it, expect, beforeEach } from 'vitest';
import {
  validateAgentJWT,
  signAgentJWT,
  generateEd25519KeyPair,
  JWTValidationError,
  _clearNonceCache,
} from '../src/jwt.js';
import type { AgentIdentityPayload } from '../src/types.js';

function makePayload(overrides: Partial<AgentIdentityPayload> = {}): AgentIdentityPayload {
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

describe('validateAgentJWT', () => {
  let keyPair: CryptoKeyPair;
  let publicKeys: Map<string, CryptoKey>;

  beforeEach(async () => {
    _clearNonceCache();
    keyPair = await generateEd25519KeyPair();
    publicKeys = new Map([['__default__', keyPair.publicKey]]);
  });

  it('validates a correctly signed token', async () => {
    const payload = makePayload();
    const token = await signAgentJWT(payload, keyPair.privateKey);
    const result = await validateAgentJWT(token, publicKeys);

    expect(result.agentId).toBe(payload.agentId);
    expect(result.operatorId).toBe(payload.operatorId);
    expect(result.capabilities).toEqual(payload.capabilities);
    expect(result.intent).toBe(payload.intent);
  });

  it('validates a token with a specific kid', async () => {
    const payload = makePayload();
    const token = await signAgentJWT(payload, keyPair.privateKey, 'key-2024');
    const keys = new Map([['key-2024', keyPair.publicKey]]);
    const result = await validateAgentJWT(token, keys);
    expect(result.agentId).toBe(payload.agentId);
  });

  it('rejects an expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const payload = makePayload({ iat: now - 7200, exp: now - 3600 });
    const token = await signAgentJWT(payload, keyPair.privateKey);

    await expect(validateAgentJWT(token, publicKeys)).rejects.toThrow(
      JWTValidationError,
    );
    await expect(validateAgentJWT(token, publicKeys)).rejects.toMatchObject({
      code: 'EXPIRED',
    });
  });

  it('rejects a token with an invalid signature', async () => {
    const payload = makePayload();
    const token = await signAgentJWT(payload, keyPair.privateKey);

    // Tamper with payload
    const parts = token.split('.');
    const tamperedPayload = btoa(
      JSON.stringify({ ...JSON.parse(atob(parts[1]!.padEnd(parts[1]!.length + (4 - (parts[1]!.length % 4)) % 4, '='))), agentId: 'evil' }),
    ).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    await expect(validateAgentJWT(tamperedToken, publicKeys)).rejects.toMatchObject({
      code: 'INVALID_SIGNATURE',
    });
  });

  it('rejects a token with missing required fields', async () => {
    const now = Math.floor(Date.now() / 1000);
    // Create payload without agentId
    const badPayload = {
      iss: 'https://issuer.example.com',
      sub: 'agent:test',
      iat: now,
      exp: now + 3600,
      nonce: crypto.randomUUID(),
      operatorId: 'openai',
      operatorDomain: 'openai.com',
      // agentId missing
      agentVersion: '1.0.0',
      capabilities: ['browse'],
      intent: 'read',
    } as unknown as AgentIdentityPayload;

    const token = await signAgentJWT(badPayload, keyPair.privateKey);
    await expect(validateAgentJWT(token, publicKeys)).rejects.toMatchObject({
      code: 'MISSING_FIELD',
    });
  });

  it('rejects a malformed token (wrong number of parts)', async () => {
    await expect(
      validateAgentJWT('not.a.valid.jwt.here', publicKeys),
    ).rejects.toMatchObject({ code: 'MALFORMED_JWT' });
  });

  it('rejects a replay attack (reused nonce)', async () => {
    const payload = makePayload();
    const token = await signAgentJWT(payload, keyPair.privateKey);

    // First validation succeeds
    await validateAgentJWT(token, publicKeys);

    // Second with same nonce fails
    // Must clear and re-sign with same nonce to bypass expiry but re-use nonce
    const token2 = await signAgentJWT(payload, keyPair.privateKey);
    await expect(validateAgentJWT(token2, publicKeys)).rejects.toMatchObject({
      code: 'REPLAY_ATTACK',
    });
  });

  it('returns walletAddress and walletChain when present', async () => {
    const payload = makePayload({
      walletAddress: '0xdeadbeef',
      walletChain: 'evm:1',
    });
    const token = await signAgentJWT(payload, keyPair.privateKey);
    const result = await validateAgentJWT(token, publicKeys);

    expect(result.walletAddress).toBe('0xdeadbeef');
    expect(result.walletChain).toBe('evm:1');
  });

  it('rejects a token with an unknown algorithm', async () => {
    const payload = makePayload();
    const token = await signAgentJWT(payload, keyPair.privateKey);
    // Replace alg in header
    const parts = token.split('.');
    const header = { alg: 'RS256', typ: 'JWT' };
    const newHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const badToken = `${newHeader}.${parts[1]}.${parts[2]}`;

    await expect(validateAgentJWT(badToken, publicKeys)).rejects.toMatchObject({
      code: 'UNSUPPORTED_ALGORITHM',
    });
  });

  it('rejects a token with no matching public key', async () => {
    const payload = makePayload();
    const token = await signAgentJWT(payload, keyPair.privateKey, 'unknown-kid');
    const keys = new Map<string, CryptoKey>(); // empty

    await expect(validateAgentJWT(token, keys)).rejects.toMatchObject({
      code: 'KEY_NOT_FOUND',
    });
  });
});
