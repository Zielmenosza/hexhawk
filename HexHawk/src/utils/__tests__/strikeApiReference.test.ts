import { describe, expect, it } from 'vitest';
import { STRIKE_API_METHODS, generateStrikeApiSchema } from '../strikeApiReference';

describe('STRIKE API reference schema', () => {
  it('documents the required discoverable STRIKE methods', () => {
    const names = STRIKE_API_METHODS.map(method => method.name);

    expect(names).toEqual(expect.arrayContaining([
      'matchIL',
      'buildXRefIndex.callersOf',
      'buildXRefIndex.calleesFrom',
      'resolveConstantAnnotation',
      'getRecoveredStructs',
      'registerHook',
      'buildFunctionIntelligence',
      'exportFunctionIntelligenceJSON',
    ]));
    expect(STRIKE_API_METHODS.every(method => method.advisory)).toBe(true);
  });

  it('generates a stable schema envelope from code references', () => {
    const schema = generateStrikeApiSchema('2026-06-27T00:00:00.000Z');

    expect(schema.schema).toBe('hexhawk.strike.api.v1');
    expect(schema.generated_at).toBe('2026-06-27T00:00:00.000Z');
    expect(schema.methods[0]).toHaveProperty('signature');
    expect(JSON.stringify(schema)).not.toContain('threatScore');
  });
});
