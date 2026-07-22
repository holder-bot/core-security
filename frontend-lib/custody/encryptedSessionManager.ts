/**
 * Enhanced session manager with AES-256-GCM encryption for sensitive data
 * Implements Phase 1 security policy: Encryption at Rest
 */

import type { SessionData, SessionConfig } from '@/types/session';
import type { WalletAddress } from '@/types/wallet';
import { getEncryptionManager } from './encryptionManager';
import {
  walletKVGetItem,
  walletKVRemoveItem,
  walletKVRemoveMatching,
  walletKVSetItem,
} from '@/lib/storage/walletKV';

const ESM_DEBUG = process.env.NEXT_PUBLIC_DEBUG_LOGS === 'true';
const esmDebugLog = (...args: any[]) => { if (ESM_DEBUG) console.log(...args); };

const DEFAULT_CONFIG: SessionConfig = {
  timeout: 30 * 60 * 1000, // 30 minutes (enhanced from 60)
  rememberSession: false,
  autoLock: true
};

const STORAGE_KEYS = {
  // Unified seed storage (v3.0)
  UNIFIED_SEEDS: 'solana_unified_seeds_v3', // New unified seed storage

  // Legacy keys for migration
  ENCRYPTED_WALLET_DATA: 'solana_encrypted_wallet_data_v2', // Old main seed storage
  ENCRYPTED_IMPORTED_SEEDS: 'solana_encrypted_imported_seeds', // Old imported seeds storage

  // Other storage
  ENCRYPTED_SESSION_DATA: 'solana_encrypted_session_data_v2', // Session management data (separate from wallet data)
  WALLET_ADDRESSES: 'solana_wallet_addresses',
  ACTIVE_ADDRESS: 'solana_wallet_active_address',
  SESSION_INFO: 'solana_session_info',
  TRANSACTION_HISTORY: 'solana_transaction_history',
  SYSTEM_LOG: 'solana_system_log',
  LEGACY_WALLET_DATA: 'solana_wallet_data',

  // JWT tokens
  ACCESS_TOKEN: 'safu_access_token',
  REFRESH_TOKEN: 'safu_refresh_token'
};

interface EncryptedWalletData {
  encryptedMnemonic: string;    // AES-256-GCM encrypted seed phrase
  publicKey: string;            // Safe to store unencrypted
  accountIndex: number;
  derivationPath: string;
  createdAt: string;
  passwordHash: string;         // For password verification
  isEncrypted: true;           // Flag to identify new format
  version: '2.0';              // Version for future migrations
}

interface LegacyWalletData {
  mnemonic: string;            // Plain text (INSECURE)
  publicKey: string;
  accountIndex: number;
  derivationPath: string;
  createdAt: string;
  hashedPassword: string;
  isEncrypted?: false;
}

interface EncryptedImportedSeed {
  seedNumber: number;          // 1, 2, 3, etc.
  encryptedMnemonic: string;   // AES-256-GCM encrypted seed phrase
  seedHash: string;            // Hash for identification
  createdAt: string;
  passwordHash: string;        // For password verification
  // Note: No network field - seeds are network-agnostic
}

interface ImportedSeedsStorage {
  seeds: { [seedNumber: string]: EncryptedImportedSeed };
  nextSeedNumber: number;
}

// UNIFIED SEED STORAGE (v3.0)
interface UnifiedSeed {
  seedNumber: number;          // 0, 1, 2, etc. (maps directly to UI buttons [0], [1], [2])
  encryptedMnemonic: string;   // AES-256-GCM encrypted seed phrase
  seedHash: string;            // Hash for identification and deduplication
  createdAt: string;
  passwordHash: string;        // For password verification
  isMain: boolean;             // true for seed [0] (original main seed), false for imported seeds
  label?: string;              // Optional custom user label
}

interface UnifiedSeedStorage {
  seeds: UnifiedSeed[];        // Array indexed by seed number: seeds[0] = main seed, seeds[1] = imported seed 1, etc.
  version: '3.0';              // Version for future migrations
}

export class EncryptedSessionManager {
  private config: SessionConfig;
  private timeoutId: NodeJS.Timeout | null = null;
  public encryptionManager = getEncryptionManager();
  private systemLogClearCallback: (() => void) | null = null;
  private webSocketCleanupCallback: (() => void) | null = null;

  constructor(config: Partial<SessionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    console.log(`🔐 Session manager initialized - Sessions expire after ${this.config.timeout / 60000} minutes for security`);
  }

  /**
   * Set callback for clearing system logs UI
   */
  setSystemLogClearCallback(callback: () => void): void {
    this.systemLogClearCallback = callback;
  }

  /**
   * Set callback for WebSocket cleanup
   */
  setWebSocketCleanupCallback(callback: () => void): void {
    this.webSocketCleanupCallback = callback;
  }

  // ===== UNIFIED SEED STORAGE (v3.0) =====

  /**
   * Load unified seed storage (creates empty storage if none exists)
   */
  private loadUnifiedSeeds(): UnifiedSeedStorage {
    try {
      const stored = walletKVGetItem(STORAGE_KEYS.UNIFIED_SEEDS);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.version === '3.0' && Array.isArray(parsed.seeds)) {
          return parsed;
        }
      }
    } catch (error) {
      console.error('Failed to load unified seeds:', error);
    }

    // Return empty unified storage
    return {
      seeds: [],
      version: '3.0'
    };
  }

  /**
   * Save unified seed storage
   */
  private saveUnifiedSeeds(storage: UnifiedSeedStorage): void {
    walletKVSetItem(STORAGE_KEYS.UNIFIED_SEEDS, JSON.stringify(storage));
    console.log(`💾 UNIFIED: Saved ${storage.seeds.length} seeds to unified storage`);
  }

  /**
   * Load a specific seed by number from unified storage
   */
  async loadUnifiedSeed(seedNumber: number, password: string): Promise<string | null> {
    try {
      const storage = this.loadUnifiedSeeds();
      const seed = storage.seeds.find(s => s.seedNumber === seedNumber);

      if (!seed) {
        console.warn(`⚠️ UNIFIED: Seed [${seedNumber}] not found in unified storage`);
        return null;
      }

      // Verify password
      const passwordHash = await this.hashPassword(password);
      if (passwordHash !== seed.passwordHash) {
        console.error(`❌ UNIFIED: Invalid password for seed [${seedNumber}]`);
        return null;
      }

      // Decrypt the seed phrase
      await this.encryptionManager.initialize();
      const decryptionResult = await this.encryptionManager.decryptSensitiveData(
        seed.encryptedMnemonic,
        password
      );

      if (!decryptionResult.success) {
        console.error(`❌ UNIFIED: Failed to decrypt seed [${seedNumber}]:`, decryptionResult.error);
        return null;
      }

      console.log(`✅ UNIFIED: Seed [${seedNumber}] (${seed.isMain ? 'main' : 'imported'}) decrypted successfully`);
      return decryptionResult.plaintext;

    } catch (error) {
      console.error(`❌ UNIFIED: Failed to load seed [${seedNumber}]:`, error);
      return null;
    }
  }

  /**
   * Save a seed to unified storage at specific position
   */
  async saveUnifiedSeed(seedNumber: number, seedPhrase: string, password: string, isMain: boolean = false, label?: string): Promise<boolean> {
    try {
      console.log(`💾 UNIFIED: Saving seed [${seedNumber}] (${isMain ? 'main' : 'imported'}) to unified storage...`);

      // Initialize encryption manager
      await this.encryptionManager.initialize();

      // Create seed hash for identification
      const seedHash = this.hashSeedPhrase(seedPhrase);

      // Hash password for verification
      const passwordHash = await this.hashPassword(password);

      // Encrypt the seed phrase
      const encryptionResult = await this.encryptionManager.encryptSensitiveData(seedPhrase, password);

      if (!encryptionResult.success) {
        throw new Error(encryptionResult.error || 'Encryption failed');
      }

      // Load existing storage
      const storage = this.loadUnifiedSeeds();

      // Ensure seeds array is large enough
      while (storage.seeds.length <= seedNumber) {
        storage.seeds.push(null as any); // Placeholder, will be replaced
      }

      // Create the unified seed entry
      const unifiedSeed: UnifiedSeed = {
        seedNumber,
        encryptedMnemonic: encryptionResult.data,
        seedHash,
        createdAt: new Date().toISOString(),
        passwordHash,
        isMain,
        label
      };

      // Store at the correct index
      storage.seeds[seedNumber] = unifiedSeed;

      // Save to localStorage
      this.saveUnifiedSeeds(storage);

      console.log(`✅ UNIFIED: Seed [${seedNumber}] (${isMain ? 'main' : 'imported'}) saved successfully`);
      return true;

    } catch (error) {
      console.error(`❌ UNIFIED: Failed to save seed [${seedNumber}]:`, error);
      return false;
    }
  }

  /**
   * Get all seeds from unified storage
   */
  getAllUnifiedSeeds(): UnifiedSeed[] {
    const storage = this.loadUnifiedSeeds();
    return storage.seeds.filter(seed => seed !== null && seed !== undefined);
  }

  /**
   * Check if unified storage has any seeds
   */
  hasUnifiedSeeds(): boolean {
    const storage = this.loadUnifiedSeeds();
    return storage.seeds.some(seed => seed !== null && seed !== undefined);
  }

  /**
   * Check if unified storage has been initialized
   */
  hasUnifiedStorage(): boolean {
    return !!walletKVGetItem(STORAGE_KEYS.UNIFIED_SEEDS);
  }

  /**
   * Migrate legacy seed storage to unified storage
   */
  async migrateToUnifiedStorage(password: string): Promise<boolean> {
    try {
      console.log('🔄 MIGRATION: Starting migration to unified seed storage...');

      // Check if already migrated with at least one seed
      if (this.hasUnifiedStorage() && this.hasUnifiedSeeds()) {
        console.log('ℹ️ MIGRATION: Unified storage already exists, skipping migration');
        return true;
      }
      if (this.hasUnifiedStorage()) {
        console.log('🔄 MIGRATION: Unified storage present but incomplete — re-running migration');
      }

      let migratedCount = 0;

      // Migrate main seed (seed [0])
      const mainSeedData = await this.loadWalletData(password);
      if (mainSeedData && mainSeedData.mnemonic) {
        console.log('🔄 MIGRATION: Migrating main seed to unified storage as seed [0]...');
        const success = await this.saveUnifiedSeed(0, mainSeedData.mnemonic, password, true, 'Main Seed');
        if (success) {
          migratedCount++;
          console.log('✅ MIGRATION: Main seed migrated successfully to seed [0]');
        } else {
          console.error('❌ MIGRATION: Failed to migrate main seed');
        }
      }

      // Migrate imported seeds
      const importedSeeds = this.getAllImportedSeeds();
      for (const importedSeed of importedSeeds) {
        try {
          console.log(`🔄 MIGRATION: Migrating imported seed #${importedSeed.seedNumber} to unified storage...`);

          // Load the imported seed
          const seedPhrase = await this.loadImportedSeed(importedSeed.seedNumber, password);
          if (seedPhrase) {
            // Save to unified storage (imported seeds start from index 1)
            const success = await this.saveUnifiedSeed(
              importedSeed.seedNumber,
              seedPhrase,
              password,
              false,
              `Imported Seed ${importedSeed.seedNumber}`
            );

            if (success) {
              migratedCount++;
              console.log(`✅ MIGRATION: Imported seed #${importedSeed.seedNumber} migrated successfully`);
            } else {
              console.error(`❌ MIGRATION: Failed to migrate imported seed #${importedSeed.seedNumber}`);
            }
          }
        } catch (error) {
          console.error(`❌ MIGRATION: Error migrating imported seed #${importedSeed.seedNumber}:`, error);
        }
      }

      console.log(`✅ MIGRATION: Migration completed - ${migratedCount} seeds migrated to unified storage`);

      // Don't remove legacy storage yet - keep for safety during testing
      console.log('ℹ️ MIGRATION: Legacy storage preserved for safety during testing');

      return migratedCount > 0;

    } catch (error) {
      console.error('❌ MIGRATION: Failed to migrate to unified storage:', error);
      return false;
    }
  }

  /**
   * Enhanced password hashing with additional rounds
   */
  async hashPassword(password: string): Promise<string> {
    console.log('Hashing password for verification...');

    const encoder = new TextEncoder();
    const data = encoder.encode(password + 'safu_salt_v2'); // Add salt

    // Multiple rounds of hashing
    console.log('JavaScript Key Access');
    let hashBuffer = await crypto.subtle.digest('SHA-256', data);
    for (let i = 0; i < 1000; i++) {
      console.log('JavaScript Key Access');
      hashBuffer = await crypto.subtle.digest('SHA-256', hashBuffer);
    }

    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    console.log('Password hashed with 1000 rounds');
    return hash;
  }

  /**
   * Save wallet data with AES-256-GCM encryption
   * ⚠️ WARNING: LEGACY FUNCTION - DO NOT USE
   * Use saveUnifiedSeed() instead for new code
   */
  async saveWalletData(walletData: any, password: string): Promise<boolean> {
    try {
      console.log('Saving wallet data with AES-256-GCM encryption...');
      // SECURITY: Mnemonic is encrypted and never logged

      // Initialize encryption manager
      await this.encryptionManager.initialize();

      // Encrypt the sensitive mnemonic
      const encryptionResult = await this.encryptionManager.encryptSensitiveData(
        walletData.mnemonic,
        password
      );

      if (!encryptionResult.success) {
        console.error('❌ Failed to encrypt mnemonic:', encryptionResult.error);
        return false;
      }

      // Hash password for verification
      const passwordHash = await this.hashPassword(password);

      // Create encrypted wallet data structure
      const encryptedWalletData: EncryptedWalletData = {
        encryptedMnemonic: encryptionResult.data,
        publicKey: walletData.publicKey,
        accountIndex: walletData.accountIndex || 0,
        derivationPath: walletData.derivationPath || "m/44'/501'/0'/0'",
        createdAt: new Date().toISOString(),
        passwordHash: passwordHash,
        isEncrypted: true,
        version: '2.0'
      };

      // Store encrypted data
      walletKVSetItem(STORAGE_KEYS.ENCRYPTED_WALLET_DATA, JSON.stringify(encryptedWalletData));

      // Clear any legacy unencrypted data for security
      const hadLegacyData = !!walletKVGetItem(STORAGE_KEYS.LEGACY_WALLET_DATA);
      walletKVRemoveItem(STORAGE_KEYS.LEGACY_WALLET_DATA);

      console.log('✅ Wallet data saved with AES-256-GCM encryption to browser localStorage');
      esmDebugLog('🔍 STORAGE_TRACE: Encrypted data length:', walletKVGetItem('solana_encrypted_wallet_data_v2')?.length);
      if (hadLegacyData) {
        console.log('🗑️ Legacy unencrypted wallet data removed from localStorage for security');
      }

      return true;
    } catch (error) {
      console.error('❌ Failed to save encrypted wallet data:', error);
      return false;
    }
  }

  /**
   * Load and decrypt wallet data
   * ⚠️ WARNING: LEGACY FUNCTION - DO NOT USE
   * Use loadUnifiedSeed() instead for new code
   */
  async loadWalletData(password?: string): Promise<any | null> {
    try {
      // Try to load encrypted data first
      const encryptedDataStr = walletKVGetItem(STORAGE_KEYS.ENCRYPTED_WALLET_DATA);

      if (encryptedDataStr) {
        console.log('Loading encrypted wallet data...');

        if (!password) {
          // Return metadata without decrypting
          const encryptedData: EncryptedWalletData = JSON.parse(encryptedDataStr);
          return {
            publicKey: encryptedData.publicKey,
            accountIndex: encryptedData.accountIndex,
            derivationPath: encryptedData.derivationPath,
            createdAt: encryptedData.createdAt,
            passwordHash: encryptedData.passwordHash,
            isEncrypted: true,
            mnemonic: null // Don't return encrypted mnemonic without password
          };
        }

        // Decrypt with password and log login
        const result = await this.decryptWalletData(encryptedDataStr, password);
        if (result) {
          console.log('🔑 LOGIN - Password verified, wallet decrypted with AES-256-GCM');
          // SECURITY: Mnemonic is never logged
        }
        return result;
      }

      // Check for legacy unencrypted data
      const legacyDataStr = walletKVGetItem(STORAGE_KEYS.LEGACY_WALLET_DATA);
      if (legacyDataStr) {
        console.log('⚠️ Found legacy unencrypted wallet data');
        const legacyData: LegacyWalletData = JSON.parse(legacyDataStr);

        // Return legacy data with warning
        return {
          ...legacyData,
          hashedPassword: legacyData.hashedPassword,
          isEncrypted: false,
          needsMigration: true
        };
      }

      return null;
    } catch (error) {
      console.error('❌ Failed to load wallet data:', error);
      return null;
    }
  }

  /**
   * Decrypt wallet data using password
   */
  private async decryptWalletData(encryptedDataStr: string, password: string): Promise<any | null> {
    try {
      const encryptedData: EncryptedWalletData = JSON.parse(encryptedDataStr);

      // Verify password
      const passwordHash = await this.hashPassword(password);
      if (passwordHash !== encryptedData.passwordHash) {
        console.warn('⚠️ Invalid password for wallet decryption');
        return null;
      }

      // Initialize encryption manager
      await this.encryptionManager.initialize();

      // Decrypt mnemonic
      console.log('Decrypting mnemonic with AES-256-GCM...');
      const decryptionResult = await this.encryptionManager.decryptSensitiveData(
        encryptedData.encryptedMnemonic,
        password
      );

      if (!decryptionResult.success) {
        console.warn('⚠️ Failed to decrypt mnemonic:', decryptionResult.error);
        return null;
      }

      console.log('✅ Wallet data decrypted successfully');

      let canonicalPublicKey = encryptedData.publicKey;
      try {
        const { getWalletManager } = await import('@/lib/wasm/managers/walletManager');
        const walletManager = getWalletManager();
        const dualResult = await walletManager.deriveDualNetworkAddresses(decryptionResult.plaintext, encryptedData.accountIndex || 0);
        if (dualResult?.success && dualResult?.solana?.address) {
          canonicalPublicKey = dualResult.solana.address;
        } else {
          const derivedSolana = await walletManager.importFromSeedPhraseWithPassword(
            decryptionResult.plaintext,
            '',
            encryptedData.accountIndex || 0
          );
          if (derivedSolana) canonicalPublicKey = derivedSolana;
        }
      } catch (deriveError) {
        console.warn('⚠️ Failed to derive canonical Solana address from decrypted mnemonic; using stored publicKey', deriveError);
      }

      if (canonicalPublicKey && canonicalPublicKey !== encryptedData.publicKey) {
        console.warn(`⚠️ Wallet metadata publicKey mismatch detected. Stored=${encryptedData.publicKey} Derived=${canonicalPublicKey}`);
        try {
          const repairedEncryptedData: EncryptedWalletData = {
            ...encryptedData,
            publicKey: canonicalPublicKey,
          };
          walletKVSetItem(STORAGE_KEYS.ENCRYPTED_WALLET_DATA, JSON.stringify(repairedEncryptedData));
          console.log(`🔧 Repaired encrypted wallet metadata publicKey to canonical derived address ${canonicalPublicKey}`);
        } catch (repairError) {
          console.warn('⚠️ Failed to persist repaired encrypted wallet metadata', repairError);
        }
      }

      // Return decrypted data
      return {
        mnemonic: decryptionResult.plaintext,
        publicKey: canonicalPublicKey,
        accountIndex: encryptedData.accountIndex,
        derivationPath: encryptedData.derivationPath,
        createdAt: encryptedData.createdAt,
        hashedPassword: encryptedData.passwordHash, // For compatibility
        isEncrypted: true
      };
    } catch (error) {
      console.warn('⚠️ Failed to decrypt wallet data (incorrect password or corrupted data):', error);
      return null;
    }
  }

  /**
   * Migrate legacy unencrypted wallet to encrypted format
   */
  async migrateLegacyWallet(password: string): Promise<boolean> {
    try {
      console.log('🔄 Starting legacy wallet migration...');

      const legacyDataStr = walletKVGetItem(STORAGE_KEYS.LEGACY_WALLET_DATA);
      if (!legacyDataStr) {
        console.log('ℹ️ No legacy wallet found to migrate');
        return true;
      }

      const legacyData: LegacyWalletData = JSON.parse(legacyDataStr);

      // Verify password against legacy hash
      const legacyPasswordHash = await this.hashPasswordLegacy(password);
      if (legacyPasswordHash !== legacyData.hashedPassword) {
        console.error('❌ Invalid password for legacy wallet migration');
        return false;
      }

      console.log('🔐 Migrating wallet to encrypted storage...');

      // Save with new encryption
      const success = await this.saveWalletData(legacyData, password);

      if (success) {
        // Remove legacy unencrypted data for security
        walletKVRemoveItem(STORAGE_KEYS.LEGACY_WALLET_DATA);
        console.log('✅ Legacy wallet migrated to AES-256-GCM encrypted format');
        console.log('🗑️ Legacy unencrypted wallet data permanently removed from localStorage');
        return true;
      } else {
        console.error('❌ Failed to migrate legacy wallet - keeping original data');
        return false;
      }
    } catch (error) {
      console.error('❌ Legacy wallet migration failed:', error);
      return false;
    }
  }

  /**
   * Legacy password hashing for migration compatibility
   */
  private async hashPasswordLegacy(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    console.log('JavaScript Key Access');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Check if wallet exists (encrypted v2, legacy, or unified seeds v3)
   */
  hasWallet(): boolean {
    // Check for encrypted wallet data (v2)
    const encryptedDataStr = walletKVGetItem(STORAGE_KEYS.ENCRYPTED_WALLET_DATA);
    if (encryptedDataStr) {
      try {
        const encryptedData = JSON.parse(encryptedDataStr);
        // Validate required fields
        if (!!(encryptedData.encryptedMnemonic && encryptedData.publicKey && encryptedData.passwordHash)) {
          return true;
        }
      } catch (error) {
        console.warn('❌ Corrupted encrypted wallet data detected, clearing...');
        walletKVRemoveItem(STORAGE_KEYS.ENCRYPTED_WALLET_DATA);
      }
    }

    // Check for legacy wallet data
    const legacyDataStr = walletKVGetItem(STORAGE_KEYS.LEGACY_WALLET_DATA);
    if (legacyDataStr) {
      try {
        const legacyData = JSON.parse(legacyDataStr);
        // Validate required fields
        if (!!(legacyData.mnemonic && legacyData.publicKey && legacyData.hashedPassword)) {
          return true;
        }
      } catch (error) {
        console.warn('❌ Corrupted legacy wallet data detected, clearing...');
        walletKVRemoveItem(STORAGE_KEYS.LEGACY_WALLET_DATA);
      }
    }

    // Check unified seed storage (v3)
    try {
      const unifiedStr = walletKVGetItem(STORAGE_KEYS.UNIFIED_SEEDS);
      if (unifiedStr) {
        const unified = JSON.parse(unifiedStr);
        const hasAnySeed = Array.isArray(unified?.seeds) && unified.seeds.some((s: any) => s !== null && s !== undefined);
        if (hasAnySeed) return true;
      }
    } catch (error) {
      console.warn('❌ Corrupted unified seed storage detected, ignoring...');
    }

    return false;
  }

  /**
   * Check if wallet needs migration from legacy format
   */
  needsMigration(): boolean {
    const hasEncrypted = !!walletKVGetItem(STORAGE_KEYS.ENCRYPTED_WALLET_DATA);
    const hasLegacy = !!walletKVGetItem(STORAGE_KEYS.LEGACY_WALLET_DATA);
    return hasLegacy && !hasEncrypted;
  }

  /**
   * Reset wallet and clear all encrypted data
   * Sequence: 1) Unsubscribe WebSockets + wait, 2) Clear logs, 3) Clear data silently, 4) Show completion
   */
  resetWallet(): void {
    // STEP 0: Fire-and-forget server-side wallet cleanup before clearing localStorage.
    // This soft-deletes api_keys, wallet_accounts, policy managers, and pending txs
    // so the next wallet session starts clean on the server side too.
    try {
      const jwt = walletKVGetItem(STORAGE_KEYS.ACCESS_TOKEN);
      if (jwt) {
        fetch('/api/wallet/reset', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${jwt}`,
            'Content-Type': 'application/json'
          }
        }).catch(() => { /* fire-and-forget: don't block reset if server is unreachable */ });
      }
    } catch {
      // Never break the reset flow
    }

    // STEP 0b: Clear httpOnly session cookie so next wallet cannot inherit prior JWT scope.
    try {
      fetch('/api/wallet/session/', { method: 'DELETE', credentials: 'same-origin' }).catch(() => {});
    } catch {
      /* never break reset */
    }

    // STEP 0c: Clear seed-backup gate (lives in page localStorage + walletKV under
    // `__safu_seed_backup_pending` — not matched by safu* prefix alone).
    try {
      // Avoid circular import at module load; dynamic require is fine here.
      const { clearSeedBackupPending } = require('@/lib/custody/seedBackupGate');
      clearSeedBackupPending();
    } catch {
      try {
        if (typeof localStorage !== 'undefined') localStorage.removeItem('__safu_seed_backup_pending');
        if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem('__safu_seed_backup_pending');
        walletKVRemoveItem('__safu_seed_backup_pending');
      } catch {
        /* ignore */
      }
    }

    // STEP 1: Immediately clear logs to prevent sensitive data from being recorded
    if (this.systemLogClearCallback) {
      this.systemLogClearCallback();
    }
    walletKVRemoveItem(STORAGE_KEYS.SYSTEM_LOG);
    console.clear();
    console.log('🧹 Clearing sensitive logs before wallet reset to prevent address leakage...');

    // STEP 2: Clear ALL wallet data from localStorage SYNCHRONOUSLY.
    // This MUST happen before any page reload — the caller may call
    // window.location.reload() immediately after resetWallet() returns.
    const itemsToRemove = [
      STORAGE_KEYS.UNIFIED_SEEDS,           // CRITICAL: Clear unified seed storage (v3.0)
      STORAGE_KEYS.ENCRYPTED_WALLET_DATA,
      STORAGE_KEYS.ENCRYPTED_IMPORTED_SEEDS,
      STORAGE_KEYS.ENCRYPTED_SESSION_DATA,
      STORAGE_KEYS.LEGACY_WALLET_DATA,
      STORAGE_KEYS.WALLET_ADDRESSES,
      STORAGE_KEYS.ACTIVE_ADDRESS,
      STORAGE_KEYS.SESSION_INFO,
      STORAGE_KEYS.TRANSACTION_HISTORY,
      STORAGE_KEYS.ACCESS_TOKEN,
      STORAGE_KEYS.REFRESH_TOKEN,
      '__safu_seed_backup_pending',
      '__walletUIReady',
    ];

    itemsToRemove.forEach(key => {
      walletKVRemoveItem(key);
    });

    // Clear ALL safu/near/mpc prefixed keys (catches activity history caches,
    // api-keys-cache, derived-addresses, policy caches, mpc cache, etc.)
    walletKVRemoveMatching((key) => {
      if (
        key.startsWith('safu') ||
        key.startsWith('__safu') ||
        key.startsWith('near-') ||
        key.startsWith('solana_') ||
        key.includes('mpc')
      ) {
        return true;
      }
      return false;
    });

    // Extension: JWTs / seed-backup flags are often ALSO in page localStorage
    // (written directly). walletKV alone is chrome.storage — leaving page LS
    // intact brings unlock screen back after remount with no vault → loop.
    try {
      if (typeof localStorage !== 'undefined') {
        const pageKeys = Object.keys(localStorage);
        for (const key of pageKeys) {
          if (
            key.startsWith('safu') ||
            key.startsWith('__safu') ||
            key.startsWith('solana_') ||
            key.startsWith('near-') ||
            key.startsWith('address-init-') ||
            key.startsWith('wallet-') ||
            key.includes('mpc')
          ) {
            localStorage.removeItem(key);
          }
        }
      }
      if (typeof sessionStorage !== 'undefined') {
        sessionStorage.clear();
      }
    } catch {
      /* ignore */
    }

    // STEP 3: Reset AccountController SYNCHRONOUSLY before any page reload
    try {
      const { AccountController } = require('@/core/controllers/AccountController');
      AccountController.resetInstance();
    } catch {
      try {
        import('@/core/controllers/AccountController').then(({ AccountController }) => {
          AccountController.resetInstance();
        }).catch(() => {});
      } catch {}
    }

    // STEP 4: Clear pending transaction caches synchronously
    try {
      const { clearPendingTransactionCaches } = require('@/lib/pendingTransactionsCache');
      clearPendingTransactionCaches();
    } catch {}

    // STEP 5: Unsubscribe from WebSockets
    if (this.webSocketCleanupCallback) {
      this.webSocketCleanupCallback();
    }

    // Async cleanup: WASM memory, logs (best-effort, may not fire before reload)
    setTimeout(() => {
      if (this.systemLogClearCallback) {
        this.systemLogClearCallback();
      }
      walletKVRemoveItem(STORAGE_KEYS.SYSTEM_LOG);
      console.clear();

      // Clear encryption keys from WASM linear memory
      this.encryptionManager.clearMemory();

      console.log('✅ Wallet reset completed - all data and logs cleared');
    }, 50); // 50ms delay to ensure WebSocket cleanup completes
  }

  /**
   * Show detailed security operations for user visibility (called after reset)
   */
  showSecurityCleanupLogs(): void {
    console.log('🗑️ Security cleanup initiated...');
    console.log('🗑️ Encrypted wallet data removed from localStorage');
    console.log('🗑️ Session data cleared from browser storage');
    console.log('🗑️ Transaction history purged');
    console.log('🦀 WASM linear memory cleared - encryption keys wiped');
    console.log('🔌 WebSocket connections terminated');
    console.log('✅ Security cleanup completed - system ready for new wallet');
  }

  /**
   * Create session with enhanced security
   */
  createSession(walletData: any, hashedPassword: string): SessionData {
    const sessionData: SessionData = {
      isAuthenticated: true,
      publicKey: walletData.publicKey,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.config.timeout,
      hashedPassword: hashedPassword,
      lastActivity: Date.now()
    };

    walletKVSetItem(STORAGE_KEYS.SESSION_INFO, JSON.stringify(sessionData));
    this.setupSessionTimeout();

    console.log(`✅ Session created successfully - Will auto-expire in ${this.config.timeout / 60000} minutes for security`);
    return sessionData;
  }

  /**
   * Enhanced session timeout with memory clearing
   */
  private setupSessionTimeout(): void {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
    }

    this.timeoutId = setTimeout(() => {
      console.log(`⏰ SESSION TIMEOUT: ${this.config.timeout / 60000} minutes expired - Auto-logout initiated for security`);
      console.log('🔒 Wallet automatically locked - Please unlock to continue');
      console.log('🗑️ Clearing WASM memory and session data for security');
      this.encryptionManager.clearMemory();
      this.logout();
    }, this.config.timeout);
  }

  /**
   * Logout with secure memory clearing
   */
  logout(): void {
    console.log('🚪 LOGOUT - Clearing session and securing memory...');

    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }

    // Clear session from localStorage (encrypted wallet data remains)
    walletKVRemoveItem(STORAGE_KEYS.SESSION_INFO);

    // Clear encryption keys from WASM linear memory
    this.encryptionManager.clearMemory();

    console.log('✅ LOGOUT completed - Session terminated, WASM memory cleared, encrypted wallet preserved');
  }

  // Delegate other methods to maintain compatibility
  loadSessionInfo(): SessionData | null {
    try {
      const sessionStr = walletKVGetItem(STORAGE_KEYS.SESSION_INFO);
      return sessionStr ? JSON.parse(sessionStr) : null;
    } catch {
      return null;
    }
  }

  checkSessionTimeout(): boolean {
    const session = this.loadSessionInfo();
    if (!session) return false;

    const now = Date.now();
    const timeRemaining = (session.expiresAt ?? 0) - now;

    if (now > (session.expiresAt ?? 0)) {
      console.log(`⏰ Session expired - Auto-logout triggered (Session was valid for ${this.config.timeout / 60000} minutes)`);
      this.logout();
      return false;
    }

    // Log remaining time for debugging (only if less than 5 minutes remaining)
    if (timeRemaining < 5 * 60 * 1000) {
      const minutesRemaining = Math.floor(timeRemaining / 60000);
      console.log(`⏳ Session expires in ${minutesRemaining} minutes (Auto-refresh will extend if activity detected)`);
    }

    return true;
  }

  // Address management methods (unchanged for now)
  saveWalletAddresses(addresses: WalletAddress[]): void {
    walletKVSetItem(STORAGE_KEYS.WALLET_ADDRESSES, JSON.stringify(addresses));
  }

  loadWalletAddresses(): WalletAddress[] {
    try {
      const addressesStr = walletKVGetItem(STORAGE_KEYS.WALLET_ADDRESSES);
      return addressesStr ? JSON.parse(addressesStr) : [];
    } catch {
      return [];
    }
  }

  hasWalletAddresses(): boolean {
    return !!walletKVGetItem(STORAGE_KEYS.WALLET_ADDRESSES);
  }

  setActiveAddress(addressId: string): void {
    walletKVSetItem(STORAGE_KEYS.ACTIVE_ADDRESS, addressId);
  }

  getActiveAddress(): string | null {
    return walletKVGetItem(STORAGE_KEYS.ACTIVE_ADDRESS);
  }

  addWalletAddress(address: WalletAddress): void {
    const addresses = this.loadWalletAddresses();
    addresses.push(address);
    this.saveWalletAddresses(addresses);
  }

  updateWalletAddress(addressId: string, updates: Partial<WalletAddress>): void {
    const addresses = this.loadWalletAddresses();
    const index = addresses.findIndex(addr => addr.id === addressId);
    if (index !== -1) {
      addresses[index] = { ...addresses[index], ...updates };
      this.saveWalletAddresses(addresses);
    }
  }

  migrateToMultiAddress(): void {
    // Implementation would go here if needed
    console.log('Multi-address migration completed');
  }

  /**
   * Save imported seed phrase with encryption (network-agnostic)
   */
  async saveImportedSeed(seedPhrase: string, password: string): Promise<number> {
    try {
      console.log('🔐 Saving imported seed with AES-256-GCM encryption...');

      // Initialize encryption manager
      await this.encryptionManager.initialize();

      // Create seed hash for identification
      const seedHash = this.hashSeedPhrase(seedPhrase);

      // Load existing imported seeds
      const importedSeeds = this.loadImportedSeeds();

      // Check if this seed already exists (network-agnostic)
      for (const [seedNum, existingSeed] of Object.entries(importedSeeds.seeds)) {
        if (existingSeed.seedHash === seedHash) {
          console.log('🔍 Seed already exists with number:', seedNum);
          return parseInt(seedNum);
        }
      }

      // Assign new seed number
      const seedNumber = importedSeeds.nextSeedNumber;

      // Hash password for verification
      const passwordHash = await this.hashPasswordLegacy(password);

      // Encrypt the seed phrase
      const encryptionResult = await this.encryptionManager.encryptSensitiveData(seedPhrase, password);

      if (!encryptionResult.success) {
        throw new Error(encryptionResult.error || 'Encryption failed');
      }

      // Create imported seed entry
      const importedSeed: EncryptedImportedSeed = {
        seedNumber,
        encryptedMnemonic: encryptionResult.data,
        seedHash,
        createdAt: new Date().toISOString(),
        passwordHash
      };

      // Save to storage
      importedSeeds.seeds[seedNumber.toString()] = importedSeed;
      importedSeeds.nextSeedNumber = seedNumber + 1;

      walletKVSetItem(STORAGE_KEYS.ENCRYPTED_IMPORTED_SEEDS, JSON.stringify(importedSeeds));

      console.log(`✅ Imported seed #${seedNumber} encrypted and stored safely`);
      return seedNumber;

    } catch (error) {
      console.error('❌ Failed to save imported seed:', error);
      throw error;
    }
  }

  /**
   * Load and decrypt imported seed by number
   * ⚠️ WARNING: LEGACY FUNCTION - DO NOT USE
   * Use loadUnifiedSeed() instead for new code
   */
  async loadImportedSeed(seedNumber: number, password: string): Promise<string | null> {
    try {
      const importedSeeds = this.loadImportedSeeds();
      const seedData = importedSeeds.seeds[seedNumber.toString()];

      if (!seedData) {
        console.error(`❌ Imported seed #${seedNumber} not found`);
        return null;
      }

      // Verify password
      const passwordHash = await this.hashPasswordLegacy(password);
      if (passwordHash !== seedData.passwordHash) {
        console.error('❌ Invalid password for imported seed');
        return null;
      }

      // Decrypt the seed phrase
      const decryptionResult = await this.encryptionManager.decryptSensitiveData(seedData.encryptedMnemonic, password);

      if (!decryptionResult.success) {
        console.error('❌ Failed to decrypt imported seed:', decryptionResult.error);
        return null;
      }

      console.log(`✅ Imported seed #${seedNumber} decrypted successfully`);
      return decryptionResult.plaintext;

    } catch (error) {
      console.error('❌ Failed to load imported seed:', error);
      return null;
    }
  }

  /**
   * Get or assign seed number for a seed phrase (network-agnostic)
   */
  async getOrAssignSeedNumber(seedPhrase: string, password: string): Promise<number> {
    const seedHash = this.hashSeedPhrase(seedPhrase);

    // At this point, unified storage should always exist due to automatic migration
    // If it doesn't exist, something is wrong and we should fail fast
    if (!this.hasUnifiedStorage()) {
      throw new Error('Unified storage not available. AddressesScreen should have migrated legacy data first.');
    }

    console.log('🔧 UNIFIED: Using unified storage for seed assignment');
    const storage = this.loadUnifiedSeeds();

    // Check if this seed already exists in unified storage
    for (const seed of storage.seeds) {
      if (seed && seed.seedHash === seedHash) {
        console.log(`🔧 UNIFIED: Found existing seed at position [${seed.seedNumber}]`);
        return seed.seedNumber;
      }
    }

    // Find the next available seed number (skip 0 which is reserved for main seed)
    let nextSeedNumber = 1;
    while (nextSeedNumber < storage.seeds.length && storage.seeds[nextSeedNumber] !== null) {
      nextSeedNumber++;
    }

    console.log(`🔧 UNIFIED: Assigning new seed number [${nextSeedNumber}]`);

    // Save new seed and return its number
    const success = await this.saveUnifiedSeed(nextSeedNumber, seedPhrase, password, false, `Imported Seed ${nextSeedNumber}`);
    if (success) {
      console.log(`✅ UNIFIED: Seed saved successfully at position [${nextSeedNumber}]`);
      return nextSeedNumber;
    } else {
      throw new Error('Failed to save seed to unified storage');
    }
  }

  /**
   * Load imported seeds storage
   */
  private loadImportedSeeds(): ImportedSeedsStorage {
    try {
      const stored = walletKVGetItem(STORAGE_KEYS.ENCRYPTED_IMPORTED_SEEDS);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.error('Failed to load imported seeds:', error);
    }

    // Return default structure
    return {
      seeds: {},
      nextSeedNumber: 1
    };
  }

  /**
   * Get all imported seeds
   */
  getAllImportedSeeds(): EncryptedImportedSeed[] {
    const importedSeeds = this.loadImportedSeeds();
    return Object.values(importedSeeds.seeds);
  }

  /**
   * Remove imported seed by number
   */
  async removeImportedSeed(seedNumber: number, password: string): Promise<boolean> {
    try {
      console.log(`🗑️ Removing imported seed #${seedNumber}...`);

      const importedSeeds = this.loadImportedSeeds();
      const seedData = importedSeeds.seeds[seedNumber.toString()];

      if (!seedData) {
        console.error(`❌ Imported seed #${seedNumber} not found`);
        return false;
      }

      // Verify password by attempting to decrypt
      await this.encryptionManager.initialize();
      const decryptionResult = await (this.encryptionManager as any).decrypt(seedData.encryptedMnemonic, password);

      if (!decryptionResult.success) {
        console.error('❌ Invalid password for seed removal');
        return false;
      }

      // Remove the seed from storage
      delete importedSeeds.seeds[seedNumber.toString()];

      // Save updated storage
      walletKVSetItem(STORAGE_KEYS.ENCRYPTED_IMPORTED_SEEDS, JSON.stringify(importedSeeds));

      console.log(`✅ Imported seed #${seedNumber} removed successfully`);
      return true;
    } catch (error) {
      console.error(`❌ Failed to remove imported seed #${seedNumber}:`, error);
      return false;
    }
  }

  /**
   * Hash seed phrase for identification (same as session manager)
   */
  private hashSeedPhrase(seedPhrase: string): string {
    let hash = 0;
    for (let i = 0; i < seedPhrase.length; i++) {
      const char = seedPhrase.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString();
  }

  /**
   * Save session management data separately from wallet data
   */
  async saveSessionData(sessionData: any, password: string): Promise<boolean> {
    try {
      console.log('Saving session data with AES-256-GCM encryption...');
      esmDebugLog('🔍 STORAGE_TRACE: Saving session data (not wallet data)');

      // Initialize encryption manager
      await this.encryptionManager.initialize();

      // Encrypt the session data (does not contain wallet mnemonic)
      const sessionDataString = JSON.stringify(sessionData);
      const encryptionResult = await this.encryptionManager.encryptSensitiveData(
        sessionDataString,
        password
      );

      if (!encryptionResult.success) {
        throw new Error(`Session encryption failed: ${encryptionResult.error}`);
      }

      // Create password hash for verification
      const passwordHash = await this.hashPassword(password);

      const encryptedSessionData = {
        encryptedData: encryptionResult.data,
        createdAt: new Date().toISOString(),
        passwordHash: passwordHash,
        isEncrypted: true,
        version: '2.0'
      };

      // Store encrypted session data in separate key (not wallet data key)
      walletKVSetItem(STORAGE_KEYS.ENCRYPTED_SESSION_DATA, JSON.stringify(encryptedSessionData));

      console.log('✅ Session data saved with AES-256-GCM encryption to browser localStorage');
      esmDebugLog('🔍 STORAGE_TRACE: Session data saved separately from wallet data');

      return true;
    } catch (error) {
      console.error('❌ Failed to save encrypted session data:', error);
      return false;
    }
  }

  /**
   * Load session management data separately from wallet data
   */
  async loadSessionData(password?: string): Promise<any | null> {
    try {
      // Load session data from separate key (not wallet data key)
      const encryptedDataStr = walletKVGetItem(STORAGE_KEYS.ENCRYPTED_SESSION_DATA);

      if (encryptedDataStr) {
        console.log('Loading encrypted session data...');

        if (!password) {
          // Return minimal info without decryption
          return {
            hasEncryptedData: true,
            isEncrypted: true,
            sessionData: null // Don't return encrypted data without password
          };
        }

        // Decrypt with password and log
        const result = await this.decryptSessionData(encryptedDataStr, password);
        if (result) {
          console.log('🔑 LOGIN - Session data decrypted with AES-256-GCM');
          esmDebugLog('🔍 STORAGE_TRACE: Session data loaded separately from wallet data');
        }
        return result;
      }

      return null;
    } catch (error) {
      console.error('❌ Failed to load session data:', error);
      return null;
    }
  }

  /**
   * Decrypt session data
   */
  private async decryptSessionData(encryptedDataStr: string, password: string): Promise<any | null> {
    try {
      const encryptedData = JSON.parse(encryptedDataStr);

      // Verify password
      const passwordHash = await this.hashPassword(password);
      if (passwordHash !== encryptedData.passwordHash) {
        console.warn('⚠️ Invalid password for session decryption');
        return null;
      }

      // Decrypt data
      await this.encryptionManager.initialize();
      const decryptionResult = await this.encryptionManager.decryptSensitiveData(
        encryptedData.encryptedData,
        password
      );

      if (!decryptionResult.success) {
        console.warn('⚠️ Session decryption failed:', decryptionResult.error);
        return null;
      }

      // Parse decrypted session data
      const sessionData = JSON.parse(decryptionResult.plaintext);

      return {
        ...sessionData,
        isEncrypted: true
      };
    } catch (error) {
      console.warn('⚠️ Session decryption error:', error);
      return null;
    }
  }
}

// Singleton instance
let encryptedSessionManagerInstance: EncryptedSessionManager | null = null;

export function getEncryptedSessionManager(): EncryptedSessionManager {
  if (!encryptedSessionManagerInstance) {
    encryptedSessionManagerInstance = new EncryptedSessionManager();
  }
  return encryptedSessionManagerInstance;
}
