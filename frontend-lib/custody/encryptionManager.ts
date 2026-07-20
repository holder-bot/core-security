/**
 * TypeScript wrapper for Rust WASM encryption functionality
 * Provides secure AES-256-GCM encryption with PBKDF2 key derivation
 */

import { initializeWasm } from '@/lib/wasm/loaders/fetchLoader';

export interface EncryptionResult {
  success: boolean;
  data: string;
  error?: string;
}

export interface DecryptionResult {
  success: boolean;
  plaintext: string;
  error?: string;
}

export interface EncryptedData {
  ciphertext: string;
  nonce: string;
  salt: string;
  iterations: number;
}

export class EncryptionManager {
  private cryptoManager: any = null;
  private isReady = false;

  async initialize(): Promise<void> {
    console.log('🔐 Initializing encryption manager...');

    try {
      const wasmModule = await initializeWasm();

      console.log('🔍 WASM module available functions:', Object.keys(wasmModule));
      console.log('🔍 CryptoManager available?', !!wasmModule.CryptoManager);
      console.log('🔍 WASM module type:', typeof wasmModule);

      if (wasmModule.CryptoManager) {
        console.log('🔐 Creating CryptoManager instance...');
        this.cryptoManager = new wasmModule.CryptoManager();
        this.isReady = true;
        console.log('✅ Encryption manager initialized with Rust WASM');
      } else {
        console.error('❌ CryptoManager not found in WASM module');
        console.log('🔍 Available:', Object.keys(wasmModule));
        throw new Error('CryptoManager not available in WASM module');
      }
    } catch (error) {
      console.error('❌ Failed to initialize encryption manager:', error);
      throw error;
    }
  }

  /**
   * Encrypt sensitive data (seed phrases, private keys) using AES-256-GCM
   */
  async encryptSensitiveData(plaintext: string, password: string): Promise<EncryptionResult> {
    if (!this.isReady || !this.cryptoManager) {
      await this.initialize();
    }

    try {
      console.log('Encrypting sensitive data with Rust WASM...');

      // Validate parameters before calling WASM
      if (!plaintext || typeof plaintext !== 'string') {
        throw new Error(`Invalid plaintext parameter: ${typeof plaintext}, value: ${plaintext}`);
      }
      if (!password || typeof password !== 'string') {
        throw new Error(`Invalid password parameter: ${typeof password}, value: ${password}`);
      }

      // Additional validation for common issues
      if (plaintext.length === 0) {
        throw new Error('Plaintext cannot be empty');
      }
      if (password.length < 8) {
        throw new Error('Password must be at least 8 characters long');
      }

      // Validate private key format if it looks like a Stellar private key
      if (plaintext.startsWith('S') && plaintext.length === 56) {
        // Stellar private key - validate base32 format
        if (!/^[A-Z2-7]{56}$/.test(plaintext)) {
          throw new Error('Invalid Stellar private key format - contains invalid characters');
        }
      }

      // Check for potential problematic characters
      if (!/^[\x20-\x7E]*$/.test(plaintext)) {
        throw new Error('Private key contains non-ASCII characters that may cause issues');
      }

      console.log('🔍 WASM encrypt params validation:', {
        plaintextType: typeof plaintext,
        plaintextLength: plaintext?.length,
        passwordType: typeof password,
        passwordLength: password?.length,
        cryptoManagerReady: !!this.cryptoManager
      });

      console.log('🔍 Calling WASM encrypt_data...');
      const result = this.cryptoManager.encrypt_data(plaintext, password);
      console.log('🔍 WASM encrypt_data result:', {
        success: result.success,
        hasData: !!result.data,
        dataLength: result.data?.length,
        error: result.error,
        errorType: typeof result.error
      });

      if (result.success) {
        console.log('✅ Data encrypted successfully');

        // Clear sensitive data from WASM memory after encryption
        this.cryptoManager.clear_memory();

        return {
          success: true,
          data: result.data
        };
      } else {
        console.error('❌ Encryption failed:', result.error);
        console.error('❌ Full WASM result object:', JSON.stringify(result, null, 2));

        // Clear memory even on failure for security
        this.cryptoManager.clear_memory();

        return {
          success: false,
          data: '',
          error: result.error || 'Unknown WASM encryption error'
        };
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown encryption error';
      console.error('❌ Encryption error:', errorMessage);

      // Clear memory on exception for security
      if (this.cryptoManager) {
        this.cryptoManager.clear_memory();
      }

      return {
        success: false,
        data: '',
        error: errorMessage
      };
    }
  }

  /**
   * Decrypt sensitive data using AES-256-GCM
   */
  async decryptSensitiveData(encryptedData: string, password: string): Promise<DecryptionResult> {
    if (!this.isReady || !this.cryptoManager) {
      await this.initialize();
    }

    try {
      console.log('Decrypting sensitive data with Rust WASM...');
      const result = this.cryptoManager.decrypt_data(encryptedData, password);

      if (result.success) {
        console.log('✅ Data decrypted successfully');

        // Clear sensitive data from WASM memory after decryption
        this.cryptoManager.clear_memory();

        return {
          success: true,
          plaintext: result.plaintext
        };
      } else {
        console.error('❌ Decryption failed:', result.error);

        // Clear memory even on failure for security
        this.cryptoManager.clear_memory();

        return {
          success: false,
          plaintext: '',
          error: result.error
        };
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown decryption error';
      console.error('❌ Decryption error:', errorMessage);

      // Clear memory on exception for security
      if (this.cryptoManager) {
        this.cryptoManager.clear_memory();
      }

      return {
        success: false,
        plaintext: '',
        error: errorMessage
      };
    }
  }

  /**
   * Test encryption round-trip to verify functionality
   */
  async testEncryption(): Promise<boolean> {
    try {
      const testData = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      const testPassword = 'TestPassword123!';

      console.log('🧪 Testing encryption round-trip...');

      // Encrypt
      const encryptResult = await this.encryptSensitiveData(testData, testPassword);
      if (!encryptResult.success) {
        console.error('❌ Encryption test failed:', encryptResult.error);
        return false;
      }

      // Decrypt
      const decryptResult = await this.decryptSensitiveData(encryptResult.data, testPassword);
      if (!decryptResult.success) {
        console.error('❌ Decryption test failed:', decryptResult.error);
        return false;
      }

      // Verify
      if (decryptResult.plaintext === testData) {
        console.log('✅ Encryption round-trip test successful');
        return true;
      } else {
        console.error('❌ Decrypted data does not match original');
        return false;
      }
    } catch (error) {
      console.error('❌ Encryption test error:', error);
      return false;
    }
  }

  /**
   * Clear sensitive data from memory
   */
  clearMemory(): void {
    if (this.cryptoManager) {
      this.cryptoManager.clear_memory();
    }
  }

  /**
   * Check if encryption manager is ready
   */
  isEncryptionReady(): boolean {
    return this.isReady && this.cryptoManager !== null;
  }
}

// Singleton instance
let encryptionManagerInstance: EncryptionManager | null = null;

export function getEncryptionManager(): EncryptionManager {
  if (!encryptionManagerInstance) {
    encryptionManagerInstance = new EncryptionManager();
  }
  return encryptionManagerInstance;
}