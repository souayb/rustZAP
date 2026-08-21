// Deliberately-vulnerable Express lab. FOR AUTHORIZED TESTING ONLY.
// Mirrors the endpoints in tests/support/lab.rs so a real scan against the
// running container yields the same confirmed findings. Also a SAST fixture:
// the req.query/req.params/req.body sinks below trigger `sast/params`.
const express = require("express");
const { exec } = require("child_process");
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/static", express.static(__dirname + "/public/static"));

// Insecure defaults: permissive CORS, no security headers, no helmet.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Server", "Express");
  res.setHeader("X-Powered-By", "Express");
  next();
});

app.get("/", (req, res) => res.sendFile(__dirname + "/public/index.html"));
app.get("/login.html", (req, res) => res.sendFile(__dirname + "/public/login.html"));
app.get("/robots.txt", (req, res) =>
  res.type("text/plain").send("User-agent: *\nDisallow: /admin/\nSitemap: /sitemap.xml\n"));
app.get("/sitemap.xml", (req, res) =>
  res.type("application/xml").send(
    `<?xml version="1.0"?><urlset><url><loc>/dast/traversal?file=a</loc></url></urlset>`));

// active DAST — vulnerable by construction
app.get("/dast/xss", (req, res) => res.send(`Results for: ${req.query.q}`)); // reflected raw
app.get("/dast/sqli", (req, res) => {
  const id = req.query.id || "";
  if (/['")]/.test(id)) return res.send("You have an error in your SQL syntax; check the manual");
  res.send("<ul><li>item</li></ul>");
});
app.get("/dast/traversal", (req, res) => {
  const f = decodeURIComponent(req.query.file || "");
  if (f.includes("etc/passwd")) return res.send("root:x:0:0:root:/root:/bin/bash\n");
  res.send("<pre>README.txt</pre>");
});
app.get("/dast/redirect", (req, res) => {
  const next = req.query.next || "";
  if (next.includes("rustzap-canary")) return res.redirect(302, next);
  res.send("home");
});
app.get("/dast/ping", (req, res) => {
  // command injection sink (child_process.exec on user input)
  exec(`echo ${req.query.host}`, (_e, out) => res.send(out || "pong"));
});
app.get("/dast/render", (req, res) => {
  // template-eval sink
  const name = decodeURIComponent(req.query.name || "");
  try { res.send(`Hello ${eval(name.replace(/[{}$]/g, ""))}`); }
  catch { res.send("Hello guest"); }
});
app.post("/dast/login", (req, res) => {
  const u = req.body.username;
  if (u && typeof u === "object") return res.json({ token: "eyJ.WELCOME.", welcome: true });
  res.status(401).json({ error: "invalid" });
});
app.post("/graphql", (req, res) =>
  res.json({ data: { __schema: { queryType: { name: "Query" } } } }));

// passive surface
app.get("/passive/cookie", (req, res) =>
  res.setHeader("Set-Cookie", "session=abc; Path=/") || res.send("ok"));
app.get("/passive/csp", (req, res) =>
  res.setHeader("Content-Security-Policy", "default-src 'unsafe-inline' *") || res.send("ok"));
app.get("/passive/leak", (req, res) =>
  res.send('password="hunter2example" token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.somesigGoesHere1234'));

// mock OpenAI endpoint — injectable, leaks a system marker (for ai_redteam)
const SYSTEM_MARKER = "rustzap-lab-secret-directive";
app.post("/v1/chat/completions", (req, res) => {
  const user = (req.body.messages || []).map((m) => m.content).join("\n");
  res.json({ choices: [{ message: { content: `${SYSTEM_MARKER}\n${user}` } }] });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`vuln-lab listening on :${PORT}`));
