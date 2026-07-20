import type { SessionData, SessionConfig } from '@/types/session';
import type { WalletAddress } from '@/types/wallet';

const DEFAULT_CONFIG: SessionConfig = {
  timeout: 60 * 60 * 1000, // 60 minutes
  rememberSession: false,
  autoLock: true
};

const STORAGE_KEYS = {
  WALLET_DATA: 'solana_wallet_data',
  WALLET_ADDRESSES: 'solana_wallet_addresses',
  ACTIVE_ADDRESS: 'solana_wallet_active_address',
  SESSION_INFO: 'solana_session_info',
  TRANSACTION_HISTORY: 'solana_transaction_history',
  SYSTEM_LOG: 'solana_system_log',
  IMPORTED_SEEDS: 'solana_imported_seeds'
};

export class SessionManager {
  private config: SessionConfig;
  private timeoutId: NodeJS.Timeout | null = null;

  constructor(config: Partial<SessionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    console.log('JavaScript Key Access');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  saveWalletData(walletData: any, hashedPassword: string): boolean {
    try {
      const encryptedData = {
        mnemonic: walletData.mnemonic,
        publicKey: walletData.publicKey,
        accountIndex: walletData.accountIndex || 0,
        derivationPath: walletData.derivationPath || "m/44'/501'/0'/0'",
        createdAt: new Date().toISOString(),
        hashedPassword: hashedPassword,
        isEncrypted: true
      };
      
      localStorage.setItem(STORAGE_KEYS.WALLET_DATA, JSON.stringify(encryptedData));
      return true;
    } catch (error) {
      console.error('Failed to save wallet data:', error);
      return false;
    }
  }

  hasWallet(): boolean {
    try {
      const stored = localStorage.getItem(STORAGE_KEYS.WALLET_DATA);
      return stored !== null;
    } catch (error) {
      console.error('Failed to check wallet existence:', error);
      return false;
    }
  }

  loadWalletData(): any | null {
    try {
      const stored = localStorage.getItem(STORAGE_KEYS.WALLET_DATA);
      return stored ? JSON.parse(stored) : null;
    } catch (error) {
      console.error('Failed to load wallet data:', error);
      return null;
    }
  }

  createSession(walletData: any, hashedPassword: string): SessionData {
    const session: SessionData = {
      isLoggedIn: true,
      walletData,
      hashedPassword,
      loginTime: Date.now(),
      lastActivity: Date.now(),
      timeout: this.config.timeout
    };

    this.saveSessionInfo(session);
    this.startSessionTimeout();
    
    return session;
  }

  saveSessionInfo(session: SessionData): void {
    try {
      const sessionInfo = {
        isLoggedIn: session.isLoggedIn,
        loginTime: session.loginTime,
        lastActivity: session.lastActivity
      };
      
      sessionStorage.setItem(STORAGE_KEYS.SESSION_INFO, JSON.stringify(sessionInfo));
    } catch (error) {
      console.error('Failed to save session info:', error);
    }
  }

  loadSessionInfo(): any | null {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEYS.SESSION_INFO);
      return stored ? JSON.parse(stored) : null;
    } catch (error) {
      console.error('Failed to load session info:', error);
      return null;
    }
  }

  updateActivity(): void {
    const sessionInfo = this.loadSessionInfo();
    if (sessionInfo) {
      sessionInfo.lastActivity = Date.now();
      this.saveSessionInfo(sessionInfo as SessionData);
    }
  }

  checkSessionTimeout(): boolean {
    const sessionInfo = this.loadSessionInfo();
    if (!sessionInfo || !sessionInfo.isLoggedIn) return false;
    
    const timeSinceActivity = Date.now() - sessionInfo.lastActivity;
    return timeSinceActivity < this.config.timeout;
  }

  private startSessionTimeout(): void {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
    }

    this.timeoutId = setTimeout(() => {
      this.logout();
    }, this.config.timeout);
  }

  logout(): void {
    sessionStorage.clear();
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
  }

  clearAllData(): void {
    localStorage.clear();
    sessionStorage.clear();
  }

  // Multi-address management methods
  saveWalletAddresses(addresses: WalletAddress[]): boolean {
    try {
      // SECURITY: Never serialize mnemonic or privateKey to localStorage
      const addressesData = addresses.map(addr => ({
        ...addr,
        mnemonic: undefined,
        privateKey: undefined
      }));
      
      localStorage.setItem(STORAGE_KEYS.WALLET_ADDRESSES, JSON.stringify(addressesData));
      return true;
    } catch (error) {
      console.error('Failed to save wallet addresses:', error);
      return false;
    }
  }

  loadWalletAddresses(): WalletAddress[] {
    try {
      const stored = localStorage.getItem(STORAGE_KEYS.WALLET_ADDRESSES);
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      console.error('Failed to load wallet addresses:', error);
      return [];
    }
  }

  hasWalletAddresses(): boolean {
    try {
      const addresses = this.loadWalletAddresses();
      return addresses.length > 0;
    } catch (error) {
      console.error('Failed to check wallet addresses:', error);
      return false;
    }
  }

  addWalletAddress(address: WalletAddress): boolean {
    try {
      const addresses = this.loadWalletAddresses();
      
      // Check if address already exists
      const existingIndex = addresses.findIndex(addr => addr.id === address.id);
      if (existingIndex !== -1) {
        // Update existing address
        addresses[existingIndex] = address;
      } else {
        // Add new address
        addresses.push(address);
      }
      
      return this.saveWalletAddresses(addresses);
    } catch (error) {
      console.error('Failed to add wallet address:', error);
      return false;
    }
  }

  removeWalletAddress(addressId: string): boolean {
    try {
      const addresses = this.loadWalletAddresses();
      const filteredAddresses = addresses.filter(addr => addr.id !== addressId);
      
      if (filteredAddresses.length === addresses.length) {
        // Address not found
        return false;
      }
      
      return this.saveWalletAddresses(filteredAddresses);
    } catch (error) {
      console.error('Failed to remove wallet address:', error);
      return false;
    }
  }

  updateWalletAddress(addressId: string, updates: Partial<WalletAddress>): boolean {
    try {
      const addresses = this.loadWalletAddresses();
      const addressIndex = addresses.findIndex(addr => addr.id === addressId);
      
      if (addressIndex === -1) {
        return false;
      }
      
      addresses[addressIndex] = { ...addresses[addressIndex], ...updates };
      return this.saveWalletAddresses(addresses);
    } catch (error) {
      console.error('Failed to update wallet address:', error);
      return false;
    }
  }

  setActiveAddress(addressId: string): boolean {
    try {
      localStorage.setItem(STORAGE_KEYS.ACTIVE_ADDRESS, addressId);
      return true;
    } catch (error) {
      console.error('Failed to set active address:', error);
      return false;
    }
  }

  getActiveAddress(): string | null {
    try {
      return localStorage.getItem(STORAGE_KEYS.ACTIVE_ADDRESS);
    } catch (error) {
      console.error('Failed to get active address:', error);
      return null;
    }
  }

  // Migration method to convert single wallet to multi-address format
  migrateToMultiAddress(): boolean {
    try {
      const existingWallet = this.loadWalletData();
      if (!existingWallet) {
        return false;
      }
      
      // Check if already migrated
      if (this.hasWalletAddresses()) {
        return true;
      }
      
      // Create primary address from existing wallet
      const primaryAddress: WalletAddress = {
        id: 'primary',
        address: existingWallet.publicKey,
        publicKey: existingWallet.publicKey,
        mnemonic: existingWallet.mnemonic || '',
        accountIndex: existingWallet.accountIndex || 0,
        derivationPath: existingWallet.derivationPath || "m/44'/501'/0'/0'",
        balance: 0,
        tokenAccounts: [],
        label: undefined,
        network: 'solana'
      };
      
      // Save as multi-address format
      this.saveWalletAddresses([primaryAddress]);
      this.setActiveAddress('primary');
      
      console.log('✅ Successfully migrated to multi-address format');
      return true;
    } catch (error) {
      console.error('Failed to migrate to multi-address format:', error);
      return false;
    }
  }

  // Legacy imported seeds management (deprecated - use encrypted session manager)
  getOrAssignSeedNumber(seedPhrase: string): number {
    console.warn('⚠️ Using legacy seed number assignment - should use encrypted session manager');
    try {
      const stored = localStorage.getItem(STORAGE_KEYS.IMPORTED_SEEDS);
      const importedSeeds: {[seedHash: string]: number} = stored ? JSON.parse(stored) : {};
      
      // Create a hash of the seed phrase (for privacy - don't store the actual seed)
      const seedHash = this.hashSeedPhrase(seedPhrase);
      
      if (importedSeeds[seedHash]) {
        return importedSeeds[seedHash];
      }
      
      // Assign new number (next available number)
      const nextNumber = Math.max(0, ...Object.values(importedSeeds)) + 1;
      importedSeeds[seedHash] = nextNumber;
      
      localStorage.setItem(STORAGE_KEYS.IMPORTED_SEEDS, JSON.stringify(importedSeeds));
      return nextNumber;
    } catch (error) {
      console.error('Failed to get/assign seed number:', error);
      return 1; // Fallback
    }
  }

  private hashSeedPhrase(seedPhrase: string): string {
    // Simple hash for seed phrases (not cryptographically secure, just for tracking)
    let hash = 0;
    for (let i = 0; i < seedPhrase.length; i++) {
      const char = seedPhrase.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString();
  }

  resetWallet(): void {
    // Clear wallet data but keep other localStorage items
    localStorage.removeItem(STORAGE_KEYS.WALLET_DATA);
    localStorage.removeItem(STORAGE_KEYS.WALLET_ADDRESSES);
    localStorage.removeItem(STORAGE_KEYS.ACTIVE_ADDRESS);
    localStorage.removeItem(STORAGE_KEYS.TRANSACTION_HISTORY);
    localStorage.removeItem(STORAGE_KEYS.SYSTEM_LOG);
    localStorage.removeItem(STORAGE_KEYS.IMPORTED_SEEDS);
    sessionStorage.clear();
    
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
  }
}

export const sessionManager = new SessionManager();