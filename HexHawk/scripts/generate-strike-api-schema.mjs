import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { STRIKE_API_METHODS } from '../src/utils/strikeApiReference.ts';

const generatedAt = process.env.HEXHAWK_STRIKE_API_GENERATED_AT ?? new Date().toISOString();
const schema = {
  schema: 'hexhawk.strike.api.v1',
  generated_at: generatedAt,
  methods: STRIKE_API_METHODS.map(method => ({
    name: method.name,
    signature: method.signature,
    description: method.description,
    advisory: method.advisory,
    verdict_pipeline: method.verdictPipeline,
    example: method.example,
  })),
};

const here = dirname(fileURLToPath(import.meta.url));
const output = resolve(here, '../../docs/strike-api.json');
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, `${JSON.stringify(schema, null, 2)}
`);
console.log(output);
