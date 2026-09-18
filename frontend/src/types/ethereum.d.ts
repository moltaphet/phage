// Minimal EIP-1193 provider typings for injected browser wallets (MetaMask, etc.).
// Avoids pulling a heavyweight web3 dependency just for the connect/disconnect flow.

export interface Eip1193RequestArgs {
  method: string;
  params?: readonly unknown[] | object;
}

export interface Eip1193Provider {
  request<T = unknown>(args: Eip1193RequestArgs): Promise<T>;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeListener(event: string, listener: (...args: unknown[]) => void): void;
  isMetaMask?: boolean;
  /** Present when multiple wallets inject themselves onto the same object. */
  providers?: Eip1193Provider[];
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider;
  }
}
