> 🇫🇷 [Version française](README.fr.md)

# Tycho Security

`@tycho/security` is the Tycho module behind `tycho security`, with the short alias `tycho sec`. Its purpose is to audit code (secrets, SBOM, CVE, Cyber Resilience Act) and deployments (external attack surface, Kubernetes CIS posture, NIS 2), and to provide a zero-trust gateway for AI agents. For the overall picture, see the [Tycho core README](https://git.qtrn.io/tycho/tycho).

## Install

```bash
tycho module add security
```

## Usage

```bash
# Code audit
tycho security code secrets         # scan Git history for leaked secrets
tycho security code sbom            # extract a CycloneDX SBOM
tycho security code cve             # match dependencies against known CVEs
tycho security code cra             # check Cyber Resilience Act compliance

# Deployment audit (alias: runtime)
tycho security deploy easm <domain> # external attack surface: DNSSEC, TLS, CSP
tycho security deploy k8s-cis       # Kubernetes CIS benchmark and security contexts
tycho security deploy passport      # signed Tycho Trust Passport (NIS 2 / ISO 27001)
tycho security deploy nis2          # NIS 2 Article 21 controls

# Zero-trust gateway
tycho security gateway              # LLM agent gateway and in-memory credential vault

tycho sec code secrets              # same commands through the short alias
```

Without a domain or action, the module prints its usage.

## Status

Early skeleton. Every command above (`code secrets|sbom|cve|cra`, `deploy easm|k8s-cis|passport|nis2`, `gateway`) is a placeholder that only prints a message; no scan or audit is performed yet.

## Licence

AGPL-3.0-only, © Quatrain Technologies. Source: https://git.qtrn.io/tycho/tycho-security
