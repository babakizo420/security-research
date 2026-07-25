# Security Research

Vulnerability research and responsible disclosure by **Kingsley Olukanni** (GitHub: [@babakizo420](https://github.com/babakizo420)).

Published CVEs in widely-used software, with a focus on **incomplete-fix analysis** (finding the residual bug a patch left behind), **cross-fork discovery** (a bug fixed upstream but still live in a fork), and the emerging **MCP / AI-agent security** class.

## Published CVEs and advisories

| CVE / Advisory | Software | Severity | Class | Write-up |
|---|---|---|---|---|
| CVE-2026-55667 | File Browser | HIGH (CVSS 8.2) | Symlink / path traversal (incomplete-fix) | [read](writeups/CVE-2026-55667-filebrowser.md) |
| CVE-2026-63131 | OpenBao | MODERATE (CVSS 6.0) | Access-control bypass (cross-fork) | [read](writeups/CVE-2026-63131-openbao.md) |
| CVE-2026-27761 | Gitea | Credited | Self-hosted Git service | [read](writeups/CVE-2026-27761-gitea.md) |
| GHSA-3frw-wjxx-2p6m | IBM mcp-context-forge (MCP Gateway) | In coordination | SSRF + credential forwarding (MCP) | details after remediation |

## Tools

- [tools/incfix](tools/incfix/) - incomplete-fix / patch-diff sibling analyzer. Reads a security fix and a codebase and lists the sibling call sites that reach the same sink but lack the guard the fix added. Includes a runnable worked example built on the real CVE-2026-27761 (Gitea) case.
- [tools/mcp-audit](tools/mcp-audit/) - defensive security self-audit for MCP servers (six SSRF, credential-forwarding, transport, DNS-rebinding, and prompt-injection check classes) plus a companion [MCP security checklist](tools/mcp-audit/MCP-SECURITY-CHECKLIST.md). Audit your own server.

## Methodology

- [How I hunt incomplete-fix and cross-fork bugs](methodology/incomplete-fix-and-cross-fork-hunting.md)
- [Architecture of an autonomous vulnerability-research pipeline](docs/autonomous-research-agent.md)

## Focus areas

- Source-code review and patch analysis
- Incomplete-fix and variant hunting
- SSRF, credential forwarding, authentication and authorization bypass, path traversal
- MCP / AI-agent security: server auth boundaries and credential handling
- Web3 and smart-contract auditing (Immunefi-cleared)

Reach me by opening an issue here or on GitHub [@babakizo420](https://github.com/babakizo420).
