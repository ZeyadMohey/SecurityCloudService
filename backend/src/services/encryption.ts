/**
 * Re-export barrel — preserves existing import paths.
 * Implementation split into fileEncryption.ts and keySharing.ts.
 */

export { encryptFile, decryptFile, IntegrityError } from './fileEncryption'
export type { EncryptFileResult } from './fileEncryption'
export { encryptFileKeyForSharing, decryptSharedFileKey } from './keySharing'
export type { SharedKeyBundle } from './keySharing'
