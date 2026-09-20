/// <reference types="vite/client" />

// Environment variables Vite inlines at build time. Declaring them here documents the
// contract and makes a typo in a variable name a build failure rather than a silent
// fallback to the default in `lib/contract.ts`.
interface ImportMetaEnv {
  /**
   * Address of the deployed PhageSentinel contract. Optional: when unset, the frontend
   * falls back to the verified studio-dev deployment hardcoded in `lib/contract.ts`.
   */
  readonly VITE_PHAGE_CONTRACT_ADDRESS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
