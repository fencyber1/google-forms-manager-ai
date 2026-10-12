import { getAuthenticatedGoogleClient, noCache, requireMethod } from '../../lib/session.js';
import { createForm } from '../../lib/forms-service.js';

export default async function handler(req, res) {
  noCache(res);
  if (!requireMethod(req, res)) return;
  const auth = await getAuthenticatedGoogleClient(req, res);
  if (!auth) return;
  const { title, questions = [] } = req.body || {};
  try {
    const created = await createForm(auth, { title, questions });
    return res.status(201).json(created);
  } catch (e) {
    if (e?.code === 'VALIDATION') return res.status(400).json({ error: e.message });
    console.error('Create form failed:', e?.message);
    return res.status(500).json({ error: 'Could not create the form. Check Google API setup and permissions.' });
  }
}
