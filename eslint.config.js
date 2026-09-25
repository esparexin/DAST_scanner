import js from '@eslint/js';

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        fetch: 'readonly',
        Response: 'readonly',
        URL: 'readonly',
        AbortController: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': 'off', // TypeScript compiler handles this with noUnusedLocals
      'no-undef': 'off',
      'no-empty': 'warn',
    },
  },
  {
    ignores: [
      '**/dist/**',
      '**/.next/**',
      '**/node_modules/**',
      '**/coverage/**',
      'infrastructure/**',
    ],
  },
];
