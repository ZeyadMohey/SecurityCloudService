import type { Config } from 'jest'

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: '.',
  testMatch: ['**/src/__tests__/**/*.test.ts'],
  modulePathIgnorePatterns: ['<rootDir>/dist/'],
  // setupFiles runs before jest globals and before any test module imports,
  // so env vars set here are visible to config/secrets.ts on first import.
  setupFiles: ['<rootDir>/jest.setup.ts'],
  testTimeout: 30_000, // PBKDF2 + bcrypt in crypto tests are intentionally slow
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.json' }],
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/__tests__/**',
    '!src/index.ts',
  ],
}

export default config
