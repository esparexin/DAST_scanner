/**
 * Properly secured test server for false-positive regression testing.
 */
import http from 'node:http';

export function createSafeServer(port: number = 9998): http.Server {
  const server = http.createServer((req, res) => {
    // All security headers present
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // Secure cookie
    res.setHeader('Set-Cookie', 'session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict');

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>Safe Server</h1></body></html>');
  });

  return server;
}
