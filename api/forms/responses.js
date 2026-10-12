import { google } from 'googleapis';
import { getAuthenticatedGoogleClient, noCache, requireMethod } from '../../lib/session.js';

export default async function handler(req, res) {
  noCache(res);
  if (!requireMethod(req, res, 'GET')) return;
  const auth = await getAuthenticatedGoogleClient(req, res);
  if (!auth) return;
  const formId = req.query.formId;
  if (!formId || typeof formId !== 'string') return res.status(400).json({ error: 'Provide formId as a query parameter.' });
  try {
    const forms = google.forms({ version: 'v1', auth });
    const result = await forms.forms.responses.list({ formId, pageSize: 500 });
    return res.status(200).json({ formId, responses: (result.data.responses || []).map(r => ({ responseId: r.responseId, createTime: r.createTime, lastSubmittedTime: r.lastSubmittedTime, answers: r.answers || {} })), nextPageToken: result.data.nextPageToken || null });
  } catch (e) {
    console.error('List responses failed:', e?.message);
    return res.status(500).json({ error: 'Could not read responses. Confirm the form ID and that the connected Google account has access.' });
  }
}
