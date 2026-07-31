# GHSA-4qxq-p5hm-3q3p - Incus: arbitrary host file read and write via VM (QEMU) driver template path traversal

- **Software:** [Incus](https://github.com/lxc/incus)
- **Severity:** HIGH (CVSS 8.5, CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)
- **Advisory:** GHSA-4qxq-p5hm-3q3p (no CVE assigned)
- **Class:** CWE-22 (path traversal) + CWE-59 (link following)
- **Type:** incomplete-fix of CVE-2026-48752
- **Fixed in:** Incus v7.3.0
- **Credit:** Kingsley Olukanni (@babakizo420), reporter. Remediation by the Incus maintainer.

## Summary

Incus applies per-instance templates when an instance starts, rendering files whose names come from the instance image or backup metadata. An authenticated user who can create a virtual machine from a custom image, or restore a VM backup, fully controls that metadata. The virtual-machine (QEMU) driver applied the template name to host file operations without validating it, so a template name containing a traversal sequence escaped the intended templates directory. This allowed reading arbitrary host files (disclosed into the guest) and writing root-owned files anywhere on the host with attacker-controlled content.

## Impact

The write primitive runs as the Incus daemon, which is root, and fires before the source is read, so it works even when the referenced source does not exist. Writing a root-owned file with chosen content to a location such as a scheduled-task directory yields host code execution. The read primitive renders an arbitrary host file into the VM configuration share that is exported to the guest, disclosing host secrets to the attacker. This crosses the guest-to-host trust boundary from an ordinary VM-creation privilege, which is why the scope is Changed and confidentiality impact is High.

## Root cause

The original vulnerability, CVE-2026-48752, was a template path traversal and symlink issue in the container code path. The remediation for that CVE hardened the LXC container driver: it confined all template writes to the instance root, rejected a template name that contained a path separator, and rejected a symlinked templates directory or template source file.

Incus has two instance types that both apply templates: containers (the LXC driver) and virtual machines (the QEMU driver). The template-application logic is duplicated per driver rather than centralized. The fix landed on the container driver only. The virtual-machine driver kept using plain file operations on the attacker-controlled template name, with none of the containment, separator rejection, or symlink checks the container driver had gained. The templates directory is host-side, under the daemon root, so the missing validation on that path was directly exploitable.

## Why it is an incomplete-fix

This is the pattern I look for after a project patches a class of bug: when a guard is added at one of several sibling call sites that reach the same sink, the sibling that did not receive the guard is the residual. Here the two sites are the container driver and the virtual-machine driver, both consuming the same untrusted template name for host file access. The published fix hardened one and left the other. Computing that set difference, the sink sites that reach the dangerous operation minus the sites the patch actually touched, points straight at the surviving bug.

A useful cross-reference sharpened the case. The upstream project that Incus forked from confines the template path in both its container and its virtual-machine drivers, using a rooted directory handle in each. Incus had ported that containment to its container driver only. So the complete remediation was already demonstrated in a sibling codebase: apply the same rooted-directory confinement to the virtual-machine driver as well.

## Fix

Incus v7.3.0 adds path validation and containment to the virtual-machine template path, bringing it in line with the container driver and rejecting traversal and symlinked template names before any host file access.

## References

- Advisory: https://github.com/lxc/incus/security/advisories/GHSA-4qxq-p5hm-3q3p
- Parent CVE: https://nvd.nist.gov/vuln/detail/CVE-2026-48752
