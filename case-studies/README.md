# Case studies (rigorous WALKs / negative results)

Audit cycles that ended in a defensible WALK, kept because the METHOD and the refuted leads are reusable. Discipline receipts: how a plausible lead was surfaced and then honestly refuted, so the next hunt is sharper.

- **cycle802-morpho-vaultv2-audit-drift** - Morpho Vaults V2 ($2.5M Immunefi continuous). Audit-drift on the freshest unaudited surface (the permissionless `BluePublicAllocator`). A bytes32-key-confusion lead on the cap check was refuted at source and empirically; 3 Foundry invariants (caps bind, value conserved) PASS at 2048 fuzz runs each. Includes the reusable drift-invariant harness.
- **cycle802-gitea-1.27.1-incomplete-fix** - Gitea 1.27.1 security batch (org-mode file-read, incomplete-SSRF allow-list, migration SSRF cluster). All three veins swept complete. The one real lead (a migration client outside the SSRF-validated transport) was refuted on reachability (hardcoded host).
