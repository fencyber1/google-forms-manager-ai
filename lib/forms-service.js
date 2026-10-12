// Server-only shared Google Forms operations.
//
// Pure functions of (auth, args): used by both the REST endpoints in
// /api/forms and the MCP tools in /lib/mcp-tools.js. They never touch
// sessions, cookies, or the network except through the Google Forms API,
// and they never log or return tokens, secrets, or keys.
import { google } from 'googleapis';

export const QUESTION_TYPES = ['short', 'paragraph', 'multiple_choice', 'checkboxes', 'dropdown'];
export const CHOICE_TYPES = ['multiple_choice', 'checkboxes', 'dropdown'];
export const MAX_QUESTIONS = 50;
export const MAX_TITLE_LENGTH = 300;

// Throws a ValidationError (message safe for clients) on bad input.
export function validateQuestions(questions) {
  if (!Array.isArray(questions) || questions.length > MAX_QUESTIONS) {
    throw validationError('Questions must be an array with no more than 50 items.');
  }
  for (const q of questions) {
    if (!q || typeof q.title !== 'string' || !q.title.trim()) {
      throw validationError('Every question needs a title.');
    }
    if (q.type && !QUESTION_TYPES.includes(q.type)) {
      throw validationError(`Unsupported question type: ${q.type}`);
    }
    if (CHOICE_TYPES.includes(q.type) && (!Array.isArray(q.options) || q.options.length < 2)) {
      throw validationError(`Question "${q.title}" needs at least two options.`);
    }
  }
  return questions;
}

export function validateTitle(title) {
  if (typeof title !== 'string' || !title.trim()) {
    throw validationError('Provide a form title.');
  }
  if (title.trim().length > MAX_TITLE_LENGTH) {
    throw validationError(`Form title must be ${MAX_TITLE_LENGTH} characters or fewer.`);
  }
  return title.trim();
}

export function validateFormId(formId) {
  if (!formId || typeof formId !== 'string' || !formId.trim()) {
    throw validationError('Provide a form ID.');
  }
  return formId.trim();
}

export function validationError(message) {
  const err = new Error(message);
  err.code = 'VALIDATION';
  return err;
}

function toQuestionRequests(questions) {
  return questions.map((q, index) => {
    const questionItem = { question: { required: Boolean(q.required) } };
    const type = q.type || 'short';
    if (type === 'short') questionItem.question.textQuestion = { paragraph: false };
    else if (type === 'paragraph') questionItem.question.textQuestion = { paragraph: true };
    else {
      const choiceType =
        type === 'multiple_choice' ? 'RADIO' : type === 'checkboxes' ? 'CHECKBOX' : 'DROP_DOWN';
      questionItem.question.choiceQuestion = {
        type: choiceType,
        options: q.options.map((value) => ({ value: String(value) })),
      };
    }
    return { createItem: { item: { title: q.title.trim(), questionItem }, location: { index } } };
  });
}

export async function createForm(auth, { title, questions = [] }) {
  const cleanTitle = validateTitle(title);
  const cleanQuestions = validateQuestions(questions);
  const forms = google.forms({ version: 'v1', auth });
  const created = await forms.forms.create({ requestBody: { info: { title: cleanTitle } } });
  const formId = created.data.formId;
  if (cleanQuestions.length) {
    await forms.forms.batchUpdate({ formId, requestBody: { requests: toQuestionRequests(cleanQuestions) } });
  }
  return {
    formId,
    title: cleanTitle,
    editUrl: `https://docs.google.com/forms/d/${formId}/edit`,
    responderUrl: created.data.responderUri || `https://docs.google.com/forms/d/${formId}/viewform`,
    questionCount: cleanQuestions.length,
  };
}

export async function getForm(auth, { formId }) {
  const id = validateFormId(formId);
  const forms = google.forms({ version: 'v1', auth });
  const result = await forms.forms.get({ formId: id });
  return {
    formId: result.data.formId,
    info: result.data.info,
    items: result.data.items || [],
    responderUri: result.data.responderUri,
    revisionId: result.data.revisionId,
  };
}

export async function listFormResponses(auth, { formId }) {
  const id = validateFormId(formId);
  const forms = google.forms({ version: 'v1', auth });
  const result = await forms.forms.responses.list({ formId: id, pageSize: 500 });
  return {
    formId: id,
    responses: (result.data.responses || []).map((r) => ({
      responseId: r.responseId,
      createTime: r.createTime,
      lastSubmittedTime: r.lastSubmittedTime,
      answers: r.answers || {},
    })),
    nextPageToken: result.data.nextPageToken || null,
  };
}
