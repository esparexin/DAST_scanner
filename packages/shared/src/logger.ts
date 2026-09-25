import pino from 'pino';

export function createLogger(name: string, level?: string): pino.Logger {
  return pino({
    name,
    level: level ?? process.env['LOG_LEVEL'] ?? 'info',
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level(label) {
        return { level: label };
      },
    },
    // Never log sensitive fields
    redact: {
      paths: [
        'password',
        'token',
        'secret',
        'apiKey',
        'authorization',
        'cookie',
        'req.headers.authorization',
        'req.headers.cookie',
        'req.headers["set-cookie"]',
        'req.headers["x-api-key"]',
      ],
      censor: '[REDACTED]',
    },
  });
}
