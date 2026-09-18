import { useCallback, useEffect, useRef, useState } from 'react';
import type { Eip1193Provider } from '../types/ethereum';
import {
  GEN_CURRENCY,
  STUDIONET_CHAIN_ID,
  STUDIONET_CHAIN_ID_HEX,
  STUDIONET_CHAIN_NAME,
  STUDIONET_EXPLORER,
  STUDIONET_RPC,
} from './contract';

// localStorage keys that persist the user's *intent* to be connected so we can
// silently re-attach on reload — and, critically, so an explicit Disconnect
// stays disconnected instead of eagerly reconnecting.
const LS_CONNECTED_KEY = 'phage.wallet.connected';
const LS_ADDRESS_KEY = 'phage.wallet.address';

export interface WalletState {
  hasProvider: boolean;
  isConnected: boolean;
  isConnecting: boolean;
  address: string | null;
  balanceGen: string | null;
  chainId: number | null;
  isCorrectNetwork: boolean;
  error: string | null;
}

export interface UseWalletResult extends WalletState {
  connect: () => Promise<string | null>;
  disconnect: () => void;
  switchNetwork: () => Promise<boolean>;
}

interface ProviderRpcError {
  code?: number;
  message?: string;
}

function getInjectedProvider(): Eip1193Provider | null {
  if (typeof window === 'undefined') return null;
  const injected = window.ethereum;
  if (!injected) return null;
  // When several wallets are installed they share window.ethereum.providers;
  // prefer MetaMask, otherwise fall back to the first injected provider.
  if (Array.isArray(injected.providers) && injected.providers.length > 0) {
    return injected.providers.find((p) => p.isMetaMask) ?? injected.providers[0];
  }
  return injected;
}

function weiHexToGen(weiHex: string): string {
  try {
    const wei = BigInt(weiHex);
    const whole = wei / 10n ** 18n;
    const frac = (wei % 10n ** 18n) / 10n ** 14n; // 4 decimal places
    return `${whole.toString()}.${frac.toString().padStart(4, '0')}`;
  } catch {
    return '0.0000';
  }
}

function parseChainId(raw: unknown): number | null {
  if (typeof raw === 'string') {
    const n = Number.parseInt(raw, 16);
    return Number.isNaN(n) ? null : n;
  }
  if (typeof raw === 'number') return raw;
  return null;
}

const INITIAL_STATE: WalletState = {
  hasProvider: false,
  isConnected: false,
  isConnecting: false,
  address: null,
  balanceGen: null,
  chainId: null,
  isCorrectNetwork: false,
  error: null,
};

export function useWallet(): UseWalletResult {
  const providerRef = useRef<Eip1193Provider | null>(null);
  // Derive provider availability during the first render so the Connect button
  // shows the correct label immediately (no setState-in-effect needed).
  const [state, setState] = useState<WalletState>(() => ({
    ...INITIAL_STATE,
    hasProvider: Boolean(getInjectedProvider()),
  }));

  const patch = useCallback((next: Partial<WalletState>) => {
    setState((prev) => ({ ...prev, ...next }));
  }, []);

  const refreshBalance = useCallback(
    async (address: string) => {
      const provider = providerRef.current;
      if (!provider) return;
      try {
        const weiHex = await provider.request<string>({
          method: 'eth_getBalance',
          params: [address, 'latest'],
        });
        patch({ balanceGen: weiHexToGen(weiHex) });
      } catch {
        patch({ balanceGen: null });
      }
    },
    [patch],
  );

  // Establish (or refresh) a live session for a given account: persist intent,
  // read the current chain, mark network correctness, and load the balance.
  const syncSession = useCallback(
    async (address: string) => {
      const provider = providerRef.current;
      if (!provider) return;
      localStorage.setItem(LS_CONNECTED_KEY, '1');
      localStorage.setItem(LS_ADDRESS_KEY, address);
      let chainId: number | null = null;
      try {
        chainId = parseChainId(await provider.request<string>({ method: 'eth_chainId' }));
      } catch {
        /* leave chainId null */
      }
      patch({
        isConnected: true,
        isConnecting: false,
        address,
        chainId,
        isCorrectNetwork: chainId === STUDIONET_CHAIN_ID,
        error: null,
      });
      await refreshBalance(address);
    },
    [patch, refreshBalance],
  );

  const resetState = useCallback(() => {
    localStorage.removeItem(LS_CONNECTED_KEY);
    localStorage.removeItem(LS_ADDRESS_KEY);
    patch({
      isConnected: false,
      isConnecting: false,
      address: null,
      balanceGen: null,
      chainId: null,
      isCorrectNetwork: false,
    });
  }, [patch]);

  const switchNetwork = useCallback(async (): Promise<boolean> => {
    const provider = providerRef.current;
    if (!provider) return false;
    try {
      await provider.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: STUDIONET_CHAIN_ID_HEX }],
      });
      return true;
    } catch (err) {
      const rpcErr = err as ProviderRpcError;
      // 4902 = the wallet doesn't know this chain yet; add it (which also selects it).
      if (rpcErr?.code === 4902) {
        try {
          await provider.request({
            method: 'wallet_addEthereumChain',
            params: [
              {
                chainId: STUDIONET_CHAIN_ID_HEX,
                chainName: STUDIONET_CHAIN_NAME,
                rpcUrls: [STUDIONET_RPC],
                nativeCurrency: GEN_CURRENCY,
                blockExplorerUrls: [STUDIONET_EXPLORER],
              },
            ],
          });
          return true;
        } catch {
          patch({ error: 'Adding the Studio-dev network was rejected.' });
          return false;
        }
      }
      if (rpcErr?.code === 4001) {
        patch({ error: 'Network switch was rejected.' });
      }
      return false;
    }
  }, [patch]);

  const connect = useCallback(async (): Promise<string | null> => {
    const provider = providerRef.current ?? getInjectedProvider();
    providerRef.current = provider;
    if (!provider) {
      patch({ error: 'No EIP-1193 wallet found. Install MetaMask to continue.' });
      return null;
    }
    patch({ isConnecting: true, error: null });
    try {
      const accounts = await provider.request<string[]>({ method: 'eth_requestAccounts' });
      if (!accounts || accounts.length === 0) {
        patch({ isConnecting: false, error: 'No accounts returned by the wallet.' });
        return null;
      }
      // Prompt the wallet to point at Studio-dev before treating the session as live.
      await switchNetwork();
      const address = accounts[0];
      await syncSession(address);
      return address;
    } catch (err) {
      const rpcErr = err as ProviderRpcError;
      let message = 'Failed to connect wallet.';
      if (rpcErr?.code === 4001) message = 'Connection request rejected.';
      else if (rpcErr?.code === -32002) message = 'A wallet request is already pending — open MetaMask.';
      else if (rpcErr?.message) message = rpcErr.message;
      patch({ isConnecting: false, error: message });
      return null;
    }
  }, [patch, switchNetwork, syncSession]);

  const disconnect = useCallback(() => {
    // dApps cannot force the extension to forget them; we tear down all local
    // session state and clear the persisted intent so we never auto-reconnect.
    resetState();
    patch({ error: null });
  }, [patch, resetState]);

  useEffect(() => {
    const provider = getInjectedProvider();
    providerRef.current = provider;
    if (!provider) return;

    const handleAccountsChanged = (...args: unknown[]) => {
      const accounts = args[0] as string[] | undefined;
      if (!accounts || accounts.length === 0) {
        // User disconnected / locked from inside the wallet extension.
        resetState();
      } else {
        void syncSession(accounts[0]);
      }
    };

    const handleChainChanged = (...args: unknown[]) => {
      const chainId = parseChainId(args[0]);
      patch({ chainId, isCorrectNetwork: chainId === STUDIONET_CHAIN_ID });
      const addr = localStorage.getItem(LS_ADDRESS_KEY);
      if (addr) void refreshBalance(addr);
    };

    const handleDisconnect = () => {
      resetState();
    };

    provider.on('accountsChanged', handleAccountsChanged);
    provider.on('chainChanged', handleChainChanged);
    provider.on('disconnect', handleDisconnect);

    // Silent reconnect only when the user previously connected and did not
    // explicitly disconnect (the localStorage flag encodes that intent).
    if (localStorage.getItem(LS_CONNECTED_KEY) === '1') {
      void (async () => {
        try {
          const accounts = await provider.request<string[]>({ method: 'eth_accounts' });
          if (accounts && accounts.length > 0) {
            await syncSession(accounts[0]);
          } else {
            resetState();
          }
        } catch {
          /* silent — leave disconnected */
        }
      })();
    }

    return () => {
      provider.removeListener('accountsChanged', handleAccountsChanged);
      provider.removeListener('chainChanged', handleChainChanged);
      provider.removeListener('disconnect', handleDisconnect);
    };
  }, [patch, refreshBalance, resetState, syncSession]);

  return { ...state, connect, disconnect, switchNetwork };
}
