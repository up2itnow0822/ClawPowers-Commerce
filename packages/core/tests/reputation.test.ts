import { describe, it, expect } from 'vitest';
import { StaticProvider } from '../src/reputation/index.js';

describe('StaticProvider', () => {
  it('returns score for known agents', async () => {
    const provider = new StaticProvider({
      'agent-1': 85,
      'agent-2': 40,
    });

    const result = await provider.lookup('agent-1');
    expect(result).not.toBeNull();
    expect(result!.score).toBe(85);
    expect(result!.provider).toBe('static');
  });

  it('returns null for unknown agents', async () => {
    const provider = new StaticProvider({});
    const result = await provider.lookup('unknown');
    expect(result).toBeNull();
  });

  it('returns default score for unknown agents when configured', async () => {
    const provider = new StaticProvider({}, 50);
    const result = await provider.lookup('unknown');
    expect(result).not.toBeNull();
    expect(result!.score).toBe(50);
  });

  it('clamps scores to 0-100 range', async () => {
    const provider = new StaticProvider({ 'over': 150, 'under': -10 });
    expect((await provider.lookup('over'))!.score).toBe(100);
    expect((await provider.lookup('under'))!.score).toBe(0);
  });

  it('allows runtime score updates', async () => {
    const provider = new StaticProvider({});
    expect(await provider.lookup('agent-1')).toBeNull();
    provider.set('agent-1', 75);
    const result = await provider.lookup('agent-1');
    expect(result!.score).toBe(75);
  });
});
