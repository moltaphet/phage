import { useState } from 'react';
import { Check, Copy, ExternalLink, X } from 'lucide-react';
import { PHAGE_CONTRACT_ADDRESS, STUDIONET_EXPLORER } from '../lib/contract';

interface DeveloperIntegrationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function DeveloperIntegrationModal({ isOpen, onClose }: DeveloperIntegrationModalProps) {
  const [activeTab, setActiveTab] = useState<'SOLIDITY' | 'PYTHON' | 'TS_JS'>('SOLIDITY');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const solidityCode = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPhageSentinel {
    function is_agent_quarantined(address target) external view returns (bool);
    function is_antibody_active(bytes32 antibody_hash) external view returns (bool);
}

contract AutonomousDeFiHub {
    IPhageSentinel public immutable phage;

    constructor() {
        phage = IPhageSentinel(${PHAGE_CONTRACT_ADDRESS});
    }

    modifier onlyHealthyAgent(address caller) {
        require(!phage.is_agent_quarantined(caller), "Phage: agent quarantined");
        _;
    }

    function executeAutonomousTask(address agent, bytes calldata payload)
        external
        onlyHealthyAgent(agent)
        returns (bool)
    {
        return true;
    }
}`;

  const pythonCode = `from genlayer_py import create_client
from genlayer_py.chains import studio_devnet

PHAGE_CONTRACT = "${PHAGE_CONTRACT_ADDRESS}"

client = create_client(chain=studio_devnet)

def verify_agent_health(agent_address: str) -> bool:
    is_quarantined = client.read_contract(
        address=PHAGE_CONTRACT,
        function_name="is_quarantined",
        args=[agent_address],
    )
    if is_quarantined:
        print(f"ALERT: {agent_address} is quarantined by Phage.")
        return False
    print(f"OK: {agent_address} is cleared.")
    return True`;

  const tsJsCode = `import { createClient } from 'genlayer-js';
import { studio-dev } from 'genlayer-js/chains';

const PHAGE_CONTRACT = "${PHAGE_CONTRACT_ADDRESS}";

const client = createClient({
  chain: studio-dev,
});

export async function checkAgentImmunity(agentAddress: string): Promise<boolean> {
  const isQuarantined = await client.readContract({
    address: PHAGE_CONTRACT,
    functionName: 'is_quarantined',
    args: [agentAddress],
  });
  return !isQuarantined;
}`;

  const currentCode = activeTab === 'SOLIDITY' ? solidityCode : activeTab === 'PYTHON' ? pythonCode : tsJsCode;

  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-labelledby="sdk-title">
      <div className="modal" style={{ width: 'min(820px, 100%)' }}>
        <div className="modal-head">
          <div>
            <h3 id="sdk-title" className="h3">Developer SDK</h3>
            <p className="help" style={{ marginTop: 4 }}>Guard execution with onlyHealthyAgent.</p>
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          <div className="cluster" style={{ justifyContent: 'space-between', gap: 10 }}>
            <div className="filter-row">
              {(['SOLIDITY', 'PYTHON', 'TS_JS'] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  className={activeTab === tab ? 'is-on' : ''}
                  onClick={() => setActiveTab(tab)}
                >
                  {tab === 'SOLIDITY' ? 'Solidity' : tab === 'PYTHON' ? 'Python' : 'TypeScript'}
                </button>
              ))}
            </div>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ minHeight: 36, fontSize: 12 }}
              onClick={() => {
                navigator.clipboard.writeText(currentCode);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
            >
              {copied ? <Check size={13} /> : <Copy size={13} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>

          <pre className="codeblock"><code>{currentCode}</code></pre>

          <div className="cards cards-2">
            <div className="pillar">
              <h4 className="h3" style={{ fontSize: 15 }}>Instant inoculation</h4>
              <p className="help" style={{ marginTop: 6 }}>
                When Phage mints an antibody, every integrated protocol inherits the block without a redeploy.
              </p>
            </div>
            <div className="pillar">
              <h4 className="h3" style={{ fontSize: 15 }}>Studio-dev</h4>
              <p className="help" style={{ marginTop: 6 }}>
                Chain 61997. RPC https://studio-dev.genlayer.com/api. Add the network to MetaMask, then connect to interact with the live contract.
              </p>
            </div>
          </div>
        </div>

        <div className="modal-foot">
          <span className="hash help">{PHAGE_CONTRACT_ADDRESS}</span>
          <div className="cluster" style={{ gap: 8 }}>
            <a
              className="btn btn-ghost"
              href={`${STUDIONET_EXPLORER}/address/${PHAGE_CONTRACT_ADDRESS}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              Explorer <ExternalLink size={12} aria-hidden="true" />
            </a>
            <button type="button" className="btn btn-stain" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
