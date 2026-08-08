# Cycle802 Lane 1 (2nd target) - Morpho Vault V2 audit-drift: VERDICT WALK (empirically-tested)

> NOTE: `00-verdict.md` in this dir is a SEPARATE Lane-1 WALK (EulerSwap 2.0) from a prior/parallel pass. This file is an INDEPENDENT second Lane-1 target (Morpho Vault V2). Both preserved; neither clobbered.

- **Target:** morpho-org/vault-v2 (Morpho Vaults V2). HEAD `b1e9005c` (2026-07-31), cloned + built on box.
- **Program:** Morpho on Immunefi - CONTINUOUS, Critical = 10% of funds affected, **max $2,500,000, min $250,000**, Immunefi Severity Classification V2.3. Also Cantina $2.5M. KYC-required (operator cleared). Immutable contracts.
- **Why this target:** fresh 2026 code, big name, high cash cap, continuous (low dup-race). New adapter/allocator architecture where audit coverage lags.
- **Security policy read first:** repo `audits/` directory (11 reports) + Immunefi program page. Severity calibrated to Immunefi funds-at-risk scale.

## Audit-coverage map (the drift surface)
`audits/` filenames give a precise coverage timeline; HEAD is 2026-07-31:
| Component | Last audit | Coverage |
|-----------|-----------|----------|
| Core VaultV2.sol (938 LOC) | 2025-09-15 | Spearbit x3, Blackthorn, ChainSecurity, Zellic, Cantina competition + **Certora formal verification** |
| MorphoMarketV1AdapterV2 (282 LOC) | 2025-12-04 | Blackthorn, Spearbit, **Certora** |
| Gates (WhitelistSend/ReceiveShares) | 2026-07-08 | Blackthorn only (single auditor) |
| **BluePublicAllocator (147 LOC)** | **NONE** | fresh Jul-2026 periphery, permissionless fund-mover, no dedicated test in repo |
| MorphoVaultV1Adapter (115 LOC) | 2025-09 core scope | - |

Freshest genuinely-unaudited surface = `src/periphery/blue-public-allocator/BluePublicAllocator.sol` (built across Jul-2026: "admin multicall", "make vaultData public", "Pack per-vault storage", "Restrict PublicAllocator to factory-created Blue adapters").

## Drift veins run

### Vein 1 - safety-net / proof-override asymmetry (bytes32-key confusion) on the unaudited allocator
**Hypothesis:** `BluePublicAllocator`'s absolute-cap check keys on `vaultBlueId(adapter, mp) = keccak256(abi.encode("this/marketParams", adapter, marketParams))` (BluePublicAllocator.sol:144-146), comment "exactly as keyed by the MorphoMarketV1AdapterV2." If that id != the id the vault tracks, `vault.allocation(allocateId)` reads 0 and the cap check is a permanent no-op (banked class: aave-v3-bytes32-mapping-key-confusion).
**Result: REFUTED (source + empirical).** Adapter per-market id = `keccak256(abi.encode("this/marketParams", address(this), marketParams))` (MorphoMarketV1AdapterV2.sol:263 + ids()[2] line 271). With `adapter == address(this)` the two abi.encode byte-strings are identical -> the cap binds. Confirmed empirically: INV-B reverts EXACTLY at the cap (a mismatched key would never revert).

### Vein 2 - permissionless value-extraction / cap-bypass via the public allocator
**Hypothesis:** permissionless `allocateFromIdle`/`reallocate` let anyone move vault funds; a caller might push a market past caps (drain the withdrawal buffer beyond allocator intent) or extract value.
**Result: REFUTED (Foundry, 2048 runs each).** A permissionless caller is strictly bounded by the public-allocator absolute cap AND the vault's own absolute+relative caps, and idle->market moves conserve totalAssets + share price. Residual griefing (relative-cap manipulation via short-term capital; frontrun-revert) is explicitly documented in the contract NatSpec (lines 19-22) = acknowledged design.

### Vein 3 - NatSpec / spec drift on core behavioral promises
`firstTotalAssets` is `transient` (VaultV2.sol:224, EIP-1153, auto-reset per tx) -> line 665 early-return is a correct within-tx idempotency cache (also the relative-cap denominator, line 595). maxRate share-price bound (accrueInterestView:671). forceDeallocate penalty <=2% per-adapter. All match documented behavior. No drift.

### Vein 4 - gates (single-auditor, freshest audited)
`setIsWhitelistedWithSig` EIP-712: per-(whitelister,account) nonce (no replay), deadline check, `block.chainid` + `address(this)` in domain (no cross-chain / cross-contract replay), recovered must be a registered whitelister. Malleability acknowledged + nonce-guarded. `canSendAssets` intermediary indirection = trusted-config (NatSpec-warned). Clean.

### Vein 5 - adapter accounting
"Donated shares lost forever", "V1.1 does not realize bad debt", "rounding-loss realizable" all documented. MarketV1AdapterV2 internal `supplyShares` tracker diverges from Morpho on-behalf donations by design (donation not counted; no deallocate underflow in normal flow). V2 adapter was Certora-verified -> a deallocate underflow would be a prime formal-verification target. No undocumented drift.

## Empirical artifact (real VaultV2 + real Morpho Blue + real MarketV1AdapterV2 + real BluePublicAllocator)
`test/DriftBluePublicAllocator.t.sol` -> copied to this dir as `DriftBluePublicAllocator.t.sol`.
```
[PASS] testInvB_permissionlessCannotExceedPublicCap(uint256,uint256) (runs: 2048)  // reverts AbsoluteCapExceeded exactly when want>pubCap; else allocation<=cap
[PASS] testInvB2_repeatedCallsStayUnderCap()                                        // repeated permissionless calls never breach the cap
[PASS] testInvC_permissionlessAllocateConservesValue(uint256) (runs: 2048)          // idle->market allocate conserves totalAssets + depositor convertToAssets
Suite result: ok. 3 passed; 0 failed.
```
(Harness note: the vault enforces BOTH absolute and relative caps; default relativeCap=0 blocks all allocation, so caps were set to WAD to make the ABSOLUTE cap the binding constraint under test. This is a harness setup detail, not a finding.)

## VERDICT: WALK (empirically-tested). No finding. No submission.
The freshest unaudited surface (BluePublicAllocator) keeps its two security promises (caps bind, value conserved) under a permissionless attacker across 2048 fuzz runs each; the strongest lead (id-key confusion) is refuted at source and empirically. Core + adapters + gates match their documented specs; residual tradeoffs are all NatSpec-acknowledged design. This is a well-audited, formally-verified, extensively-documented codebase.

## Honest coverage boundary (scheduled residuals, not a forced finding)
- `reallocate` two-market interleaving (deallocate A -> allocate B) under a STATEFUL invariant handler + a concurrent privileged cap/timelock change (INV-C only exercised idle->single-market).
- `multicall` delegatecall batching of `reallocate`/`allocateFromIdle` when `nativePenalty > 0` (source-reasoned safe: multicall nonpayable -> msg.value==0 forces nativePenalty==0; no penalty reuse). Not fuzzed.
- MarketV1AdapterV2 on-behalf-donation share-price manipulation vs `expectedSupplyAssets` (source-reasoned "donated shares lost forever"; not fuzzed).
