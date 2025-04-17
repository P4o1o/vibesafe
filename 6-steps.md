Phase 6: Additional Common Checks
6.3 Exposed Debug/Admin Endpoints
 Extend file traversal to include:

Express router files (src/routes/**)

Next.js API routes (pages/api/, app/api/)

 Scan each .js/.ts file for sensitive-path definitions using regex or AST, e.g.
app.(get|post|put|delete)('/(admin|debug|status|info)'
router.(get|post)('/(admin|debug|status|info)'

 Record each match as a JSON object:
{ "file": "src/routes/admin.js", "line": 42, "path": "/admin" }

 In each matched file, scan imports for auth libraries:

passport

express-session

jsonwebtoken

next-auth

@clerk/clerk-sdk-node

 In the handler code, look for auth-usage patterns:

if (!req.user)

await getSession()

jwt.verify()

 Flag endpoint if a sensitive route is found and no auth import or auth-usage pattern is detected

6.4 Lack of Rate‑Limiting in HTTP Clients
 Detect HTTP libraries in package.json:

axios

node-fetch

cross-fetch

got

superagent

 AST scan each .js/.ts file for call expressions:

axios.<method>(url, config?)

fetch(url, options?)

 For each call, inspect arguments:

axios: if only one argument or config missing timeout/signal, mark missing timeout

fetch: if no AbortController usage (new AbortController() or signal:), mark missing timeout

 Emit JSON per finding: { "file": "src/api.js", "line": 27, "library": "axios", "call": "axios.get", "missing": ["timeout"] }

 Add CLI flag (e.g. --check-timeouts) to include these findings in the report

6.5 Insufficient Logging & Error Sanitization
 AST scan for all CallExpression where callee is:

console.log

console.error

console.warn

console.debug

logger methods from known libs (e.g. winston, pino)

 For each log call:

If single argument is an Identifier named err/error or a MemberExpression ending in .stack, flag as unsanitized-error

If any argument source text matches /password|email|token|ssn|secret/, flag as pii-logging

 Emit JSON per finding: { "file": "src/app.js", "line": 123, "type": "pii-logging", "snippet": "console.error(User email: ${user.email})" }

 Group and summarize findings by file in the final report