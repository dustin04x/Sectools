// TypeScript type definitions for SecTools

// History entry
export interface HistoryEntry {
  id: string;
  module_type: ModuleType;
  input_data: Record<string, any>;
  output_data: Record<string, any>;
  timestamp: string;
  bookmarked: boolean;
}

// Bookmark entry
export interface Bookmark {
  id: string;
  title: string;
  module_type: ModuleType;
  payload: string;
  data: Record<string, any>;
  tags: string[];
  created_at: string;
}

// Module types
export type ModuleType = 
  | 'port-scanner'
  | 'crypto'
  | 'ip-tools'
  | 'rev-shell'
  | 'web-tools';

// Navigation item
export interface NavItem {
  id: ModuleType | 'dashboard';
  label: string;
  icon: string;
  href: string;
  description?: string;
}

// Port Scanner types
export interface PortRange {
  start: number;
  end: number;
}

export interface ScanOptions {
  threads: number;
  timeout: number;
}

// Crypto types
export type CryptoAlgorithm = 
  | 'AES-256' 
  | 'RSA' 
  | 'Base64' 
  | 'URL' 
  | 'Hex'
  | 'ROT13';

export type HashAlgorithm = 
  | 'MD5' 
  | 'SHA-1' 
  | 'SHA-256' 
  | 'SHA-512' 
  | 'SHA3-256'
  | 'SHA3-512'
  | 'BLAKE2b'
  | 'bcrypt';

export type CryptoOperation = 'encrypt' | 'decrypt' | 'hash';

// IP Tools types
export type IPQueryType = 'geolocation' | 'reversedns' | 'whois';

// Reverse Shell types
export type ShellLanguage = 
  | 'bash' 
  | 'python' 
  | 'php' 
  | 'perl' 
  | 'ruby' 
  | 'powershell' 
  | 'netcat'
  | 'ncat';

export type ShellPlatform = 'linux' | 'windows' | 'macos';

export type PayloadEncoding = 'none' | 'base64' | 'url' | 'doubleurl';

// UI State
export interface UIState {
  sidebarOpen: boolean;
  activeModule: ModuleType | 'dashboard';
  commandPaletteOpen: boolean;
}

// Toast notification
export interface Toast {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message?: string;
  duration?: number;
}

// User preferences
export interface UserPreferences {
  theme: 'dark' | 'light' | 'system';
  defaultThreads: number;
  defaultTimeout: number;
  saveHistory: boolean;
  autoExport: boolean;
}
