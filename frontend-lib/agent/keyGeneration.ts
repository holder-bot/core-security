import crypto from 'crypto';
import { promisify } from 'util';

const pbkdf2 = promisify(crypto.pbkdf2);

export interface KeyGenerationResult {
  keyId: string;
  apiKey: string;
  encryptedPrivateKey: string;
  apiKeyHash: string;
  encryptionSalt: string;
}

export interface KeyMetadata {
  name?: string;
  description?: string;
}

/**
 * Generates a cryptographically secure random string
 * @param bits Number of bits of entropy (default: 256)
 * @returns Base64-encoded random string
 */
export function generateSecureRandom(bits: number = 256): string {
  const bytes = bits / 8;
  return crypto.randomBytes(bytes).toString('base64').replace(/[/+=]/g, '');
}

/**
 * Generates a UUID v4
 */
export function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Creates SHA-256 hash of input
 */
export async function sha256(input: string): Promise<string> {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Derives encryption key from API key using PBKDF2
 */
export async function deriveEncryptionKey(
  apiKey: string, 
  salt: string, 
  iterations: number = 100000
): Promise<Buffer> {
  return await pbkdf2(apiKey, salt, iterations, 32, 'sha256');
}

/**
 * Encrypts data using AES-256-GCM
 */
export function encryptAES256GCM(plaintext: string, key: Buffer): {
  encrypted: string;
  iv: string;
  authTag: string;
} {
  // Use require to avoid Webpack bundling issues
  const crypto = require('crypto');
  
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('safu-agent-v2')); // Additional authenticated data
  
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

/**
 * Decrypts data using AES-256-GCM
 */
export function decryptAES256GCM(
  encryptedData: { encrypted: string; iv: string; authTag: string },
  key: Buffer
): string {
  // Use require to avoid Webpack bundling issues
  const crypto = require('crypto');
  
  const iv = Buffer.from(encryptedData.iv, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from('safu-agent-v2'));
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'base64'));
  
  let plaintext = decipher.update(encryptedData.encrypted, 'base64', 'utf8');
  plaintext += decipher.final('utf8');
  
  return plaintext;
}

/**
 * Generates a complete API key with encrypted private key storage
 * @param publicKey The public key for this API key
 * @param privateKeyOrEncrypted Either plaintext private key (legacy) or already-encrypted private key (secure)
 * @param metadata Optional metadata
 * @param isAlreadyEncrypted Whether the private key is already encrypted (default: false for backward compatibility)
 */
export async function generateAPIKey(
  publicKey: string,
  privateKeyOrEncrypted: string,
  metadata: KeyMetadata = {},
  isAlreadyEncrypted: boolean = false
): Promise<KeyGenerationResult> {
  // Generate unique identifiers
  const keyId = generateUUID();
  const apiKey = generateSecureRandom(256); // 256-bit API key
  
  let encryptedPrivateKey: string;
  let salt: string;
  
  if (isAlreadyEncrypted) {
    // SECURE: Private key is already encrypted client-side, just use it
    console.log(`[AGENT-KEYGEN] Using pre-encrypted private key (SECURE)`);
    encryptedPrivateKey = privateKeyOrEncrypted;
    salt = 'client-encrypted'; // Mark that this was encrypted client-side
  } else {
    // LEGACY: Encrypt the plaintext private key (less secure)
    console.log(`[AGENT-KEYGEN] Encrypting plaintext private key (LEGACY)`);
    
    // Generate salt for PBKDF2
    salt = generateSecureRandom(256);
    
    // Derive encryption key from API key
    const encryptionKey = await deriveEncryptionKey(apiKey, salt);
    
    // Encrypt private key
    const encryptionResult = encryptAES256GCM(privateKeyOrEncrypted, encryptionKey);
    encryptedPrivateKey = JSON.stringify(encryptionResult);
  }
  
  // Hash API key for storage (don't store plaintext)
  const apiKeyHash = await sha256(apiKey);
  
  // Log generation (without sensitive data)
  console.log(`[AGENT-KEYGEN] Generated API key for address ${publicKey.slice(0, 8)}...${publicKey.slice(-8)}`);
  console.log(`[AGENT-KEYGEN] Key ID: ${keyId}`);
  console.log(`[AGENT-KEYGEN] Metadata:`, metadata);
  console.log(`[AGENT-KEYGEN] Security mode: ${isAlreadyEncrypted ? 'SECURE (client-encrypted)' : 'LEGACY (server-encrypted)'}`);
  
  return {
    keyId,
    apiKey, // Only returned once - must be stored by caller
    encryptedPrivateKey,
    apiKeyHash,
    encryptionSalt: salt
  };
}

/**
 * Decrypts a private key using the original API key
 */
export async function decryptPrivateKey(
  encryptedPrivateKey: string,
  apiKey: string,
  encryptionSalt: string
): Promise<string> {
  try {
    // Derive the same encryption key
    const encryptionKey = await deriveEncryptionKey(apiKey, encryptionSalt);
    
    // Parse encrypted data
    const encryptionData = JSON.parse(encryptedPrivateKey);
    
    // Decrypt private key
    const privateKey = decryptAES256GCM(encryptionData, encryptionKey);
    
    return privateKey;
  } catch (error) {
    console.error('[AGENT-KEYGEN] Failed to decrypt private key:', error);
    throw new Error('Failed to decrypt private key');
  }
}

/**
 * Validates an API key against its hash
 */
export async function validateAPIKey(apiKey: string, apiKeyHash: string): Promise<boolean> {
  try {
    const computedHash = await sha256(apiKey);
    return computedHash === apiKeyHash;
  } catch (error) {
    console.error('[AGENT-KEYGEN] Failed to validate API key:', error);
    return false;
  }
}

/**
 * Generates positions for partial key challenge
 */
export function generateChallengePositions(keyLength: number = 64, numPositions: number = 5): number[] {
  const positions: number[] = [];
  const availablePositions = Array.from({ length: keyLength }, (_, i) => i);
  
  // Randomly select positions without replacement
  for (let i = 0; i < numPositions && availablePositions.length > 0; i++) {
    const randomIndex = crypto.randomInt(0, availablePositions.length);
    positions.push(availablePositions.splice(randomIndex, 1)[0]);
  }
  
  return positions.sort((a, b) => a - b);
}

/**
 * Extracts key fragments at specified positions
 */
export function extractKeyFragments(apiKey: string, positions: number[]): string[] {
  return positions.map(pos => apiKey.charAt(pos));
}

/**
 * Validates key fragments against expected values
 */
export function validateKeyFragments(
  apiKey: string, 
  positions: number[], 
  providedFragments: string[]
): boolean {
  if (positions.length !== providedFragments.length) {
    return false;
  }
  
  const expectedFragments = extractKeyFragments(apiKey, positions);
  
  for (let i = 0; i < expectedFragments.length; i++) {
    if (expectedFragments[i] !== providedFragments[i]) {
      return false;
    }
  }
  
  return true;
}