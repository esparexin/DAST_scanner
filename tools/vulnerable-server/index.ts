import { createVulnerableServer } from '../../tests/fixtures/vulnerable-server.js';

const PORT = parseInt(process.env['PORT'] ?? '9999', 10);
const server = createVulnerableServer(PORT);

server.listen(PORT, () => {
  console.log(`[Vulnerable Server] Running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log(`  - GET http://localhost:${PORT}/ (Directory index)`);
  console.log(`  - GET http://localhost:${PORT}/search?q=<query> (SQLi + XSS)`);
  console.log(`  - GET http://localhost:${PORT}/download?file=<path> (Path Traversal)`);
});

const shutdown = () => {
  console.log('\n[Vulnerable Server] Stopping...');
  server.close(() => {
    process.exit(0);
  });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

export { server, createVulnerableServer };
