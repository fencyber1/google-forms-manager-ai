import { getAuthenticatedGoogleClient, noCache, requireMethod } from '../../lib/session.js';
import { getForm } from '../../lib/forms-service.js';

export default async function handler(req, res) {
  noCache(res);
  if (!requireMethod(req, res, 'GET')) return;
  const auth = await getAuthenticatedGoogleClient(req, res);
  if (!auth) return;
  const formId = req.query.formId;
  if (!formId || typeof formId !== 'string') return res.status(400).json({ error: 'Provide formId as a query parameter.' });
  try {
    const result = await getForm(auth, { formId });
    return res.status(200).json(result);
  } catch (e) {
    if (e?.code === 'VALIDATION') return res.status(400).json({ error: e.message });
    console.error('Get form failed:', e?.message);
    return res.status(500).json({ error: 'Could not read this form. Confirm the form ID and that the connected Google account has access.' });
  }
}
