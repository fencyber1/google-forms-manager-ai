// Input validation: schemas accept good input and reject bad input,
// including unknown identity-override fields (strict objects).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createGoogleFormSchema, formIdSchema } from '../lib/mcp-tools.js';
import { validateQuestions, validateTitle, validateFormId } from '../lib/forms-service.js';

describe('mcp input validation', () => {
  it('accepts a valid create_google_form payload', () => {
    const parsed = createGoogleFormSchema.parse({
      title: 'Team lunch',
      questions: [{ title: 'Name?', type: 'short', required: true }],
    });
    assert.equal(parsed.title, 'Team lunch');
    assert.equal(parsed.questions[0].type, 'short');
  });

  it('applies defaults for omitted optionals', () => {
    const parsed = createGoogleFormSchema.parse({ title: 'T' });
    assert.deepEqual(parsed.questions, []);
  });

  it('rejects missing title, bad types, and too many questions', () => {
    assert.throws(() => createGoogleFormSchema.parse({ questions: [] }));
    assert.throws(() => createGoogleFormSchema.parse({ title: 'T', questions: [{ title: 'Q', type: 'essay' }] }));
    assert.throws(() =>
      createGoogleFormSchema.parse({
        title: 'T',
        questions: Array.from({ length: 51 }, (_, i) => ({ title: `Q${i}` })),
      }),
    );
  });

  it('rejects unknown fields such as userId or email (strict schemas)', () => {
    assert.throws(() => createGoogleFormSchema.parse({ title: 'T', userId: '123' }));
    assert.throws(() => formIdSchema.parse({ formId: 'abc', email: 'a@b.c' }));
  });

  it('rejects missing or empty formId', () => {
    assert.throws(() => formIdSchema.parse({}));
    assert.throws(() => formIdSchema.parse({ formId: '' }));
  });

  it('service validators throw VALIDATION errors with safe messages', () => {
    assert.throws(() => validateTitle('  '), /Provide a form title/);
    assert.throws(() => validateFormId(''), /Provide a form ID/);
    assert.throws(() => validateQuestions([{ title: '   ' }]), /Every question needs a title/);
    assert.throws(
      () => validateQuestions([{ title: 'Q', type: 'multiple_choice', options: ['only-one'] }]),
      /at least two options/,
    );
    try {
      validateTitle(null);
      assert.fail('expected throw');
    } catch (e) {
      assert.equal(e.code, 'VALIDATION');
    }
  });
});
