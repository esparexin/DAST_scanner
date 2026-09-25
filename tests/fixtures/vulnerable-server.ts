/**
 * Intentionally vulnerable test server for detection regression testing.
 * This server has KNOWN vulnerabilities for testing the scanner against.
 * DO NOT deploy this anywhere except local testing.
 */
import http from 'node:http';

export function createVulnerableServer(port: number = 9999): http.Server {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${port}`);

    // Missing security headers (SEC-HDR-001 through SEC-HDR-004)
    // No HSTS, no X-Content-Type-Options, no X-Frame-Options, no CSP
    res.setHeader('X-Powered-By', 'Express/4.18.0'); // SEC-HDR-006
    res.setHeader('Server', 'Apache/2.4.41'); // SEC-HDR-005
    res.setHeader('Access-Control-Allow-Origin', '*'); // SEC-CORS-001

    // Set insecure cookie (SEC-COOKIE-001, 002, 003)
    res.setHeader('Set-Cookie', 'session=abc123; Path=/');

    if (url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><body>
        <h1>Vulnerable Test App</h1>
        <a href="/page1">Page 1</a>
        <a href="/api/users">Users API</a>
        <form action="/login" method="POST">
          <input name="username" type="text">
          <input name="password" type="password">
          <button type="submit">Login</button>
        </form>
      </body></html>`);
    } else if (url.pathname === '/page1') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Page 1</h1><a href="/">Home</a></body></html>');
    } else if (url.pathname === '/api/users') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ users: [{ id: 1, name: 'admin', email: 'admin@test.com' }] }));
    } else if (url.pathname === '/api/users/1') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: 1, name: 'admin', email: 'admin@test.com', password: 'exposed!' }));
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  });

  return server;
}
