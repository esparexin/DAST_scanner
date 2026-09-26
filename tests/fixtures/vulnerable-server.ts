/**
 * Intentionally vulnerable test server for detection regression testing.
 * This server has KNOWN vulnerabilities for testing the scanner against.
 * Strictly for local automated regression tests.
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
    res.setHeader('Set-Cookie', 'session=abc123; Path=/'); // Insecure cookie

    if (url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><body>
        <h1>Vulnerable Test App</h1>
        <a href="/search?q=test">Search</a>
        <a href="/download?file=doc.txt">Download</a>
      </body></html>`);
    } else if (url.pathname === '/search') {
      const q = url.searchParams.get('q') ?? '';
      // SQL injection vulnerability simulation
      if (q.includes("'") || q.includes('"')) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('PostgreSQL: syntax error at or near "\'" at line 1');
        return;
      }
      // XSS reflection vulnerability simulation
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><body>Search results for: ${q}</body></html>`);
    } else if (url.pathname === '/download') {
      const file = url.searchParams.get('file') ?? '';
      // Path traversal vulnerability simulation
      if (file.includes('etc/passwd')) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('root:x:0:0:root:/root:/bin/bash\
bin:x:1:1:bin:/bin:/sbin/nologin');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Sample document content');
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  });

  return server;
}
