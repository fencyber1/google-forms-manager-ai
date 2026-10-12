import { google } from 'googleapis';
import { requireMethod, requireSession, noCache } from '../../lib/session.js';

export default async function handler(req, res) {
  noCache(res);
  if (!requireMethod(req, res)) return;
  const tokens = requireSession(req, res); if (!tokens) return;
  const { title, questions = [] } = req.body || {};
  if (typeof title !== 'string' || !title.trim()) return res.status(400).json({ error: 'Provide a form title.' });
  if (!Array.isArray(questions) || questions.length > 50) return res.status(400).json({ error: 'Questions must be an array with no more than 50 items.' });
  for (const q of questions) {
    if (!q || typeof q.title !== 'string' || !q.title.trim()) return res.status(400).json({ error: 'Every question needs a title.' });
    if (q.type && !['short', 'paragraph', 'multiple_choice', 'checkboxes', 'dropdown'].includes(q.type)) return res.status(400).json({ error: `Unsupported question type: ${q.type}` });
    if (['multiple_choice', 'checkboxes', 'dropdown'].includes(q.type) && (!Array.isArray(q.options) || q.options.length < 2)) return res.status(400).json({ error: `Question "${q.title}" needs at least two options.` });
  }
  try {
    const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
    auth.setCredentials(tokens);
    const forms = google.forms({ version: 'v1', auth });
    const created = await forms.forms.create({ requestBody: { info: { title: title.trim() } } });
    const formId = created.data.formId;
    if (questions.length) {
      const requests = questions.map((q, index) => {
        const questionItem = { question: { required: Boolean(q.required) } };
        const type = q.type || 'short';
        if (type === 'short') questionItem.question.textQuestion = { paragraph: false };
        else if (type === 'paragraph') questionItem.question.textQuestion = { paragraph: true };
        else {
          const choiceType = type === 'multiple_choice' ? 'RADIO' : type === 'checkboxes' ? 'CHECKBOX' : 'DROP_DOWN';
          questionItem.question.choiceQuestion = { type: choiceType, options: q.options.map(value => ({ value: String(value) })) };
        }
        return { createItem: { item: { title: q.title.trim(), questionItem }, location: { index } } };
      });
      await forms.forms.batchUpdate({ formId, requestBody: { requests } });
    }
    return res.status(201).json({ formId, title: title.trim(), editUrl: `https://docs.google.com/forms/d/${formId}/edit`, responderUrl: created.data.responderUri || `https://docs.google.com/forms/d/${formId}/viewform`, questionCount: questions.length });
  } catch (e) {
    console.error('Create form failed:', e?.message);
    return res.status(500).json({ error: 'Could not create the form. Check Google API setup and permissions.' });
  }
}
