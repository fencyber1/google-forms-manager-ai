export default function handler(req, res) {
  res.status(200).json({
    ok: true,
    service: "Google Forms Manager AI backend",
    note: "Backend is deployed. Google OAuth must be configured before Forms operations can be used."
  });
}
