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
tycho security deploy credentials   # factory default credentials (static; --live on a cluster)
tycho security deploy easm <domain> # external attack surface: DNSSEC, TLS, CSP
tycho security deploy k8s-cis       # Kubernetes CIS benchmark and security contexts
tycho security deploy passport      # signed Tycho Trust Passport (NIS 2 / ISO 27001)
tycho security deploy nis2          # NIS 2 Article 21 controls

# Zero-trust gateway
tycho security gateway              # LLM agent gateway and in-memory credential vault

tycho sec code secrets              # same commands through the short alias
```

Without a domain or action, the module prints its usage.

## Factory default credentials audit

`tycho security deploy credentials` implements the controls of the knowledge unit
*Factory Default Credentials* (AGENTS.okf, `content/cybersecurity/factory-default-credentials.md`).
It reads a recipe provider descriptor: `.tycho/repository.json` (variables) and
`.tycho/recipes/<engine>/<recipe>/package.json`, field `tycho.credentials`.

```bash
tycho security deploy credentials --recipes <provider-repo>              # static controls
tycho security deploy credentials --recipes <provider-repo> --live \
    --context <kubectl-context>                                           # + live controls
tycho security deploy credentials --recipe <name> --format json          # one recipe, JSON report
```

| Control | Kind | Fails when |
| :--- | :--- | :--- |
| `credentials.declared` | static | the recipe does not declare its factory accounts (`[]` when none) |
| `credentials.login-replaced` | static | the factory login is kept: no login variable, a default or a well-known example |
| `credentials.secret-sourced` | static | a login or password variable is not a required secret without default |
| `credentials.exposure-order` | static | the public route is not published after the replacement |
| `credentials.factory-rejected` | live | the running service accepts the factory pair |
| `credentials.factory-login-retired` | live | the running service accepts the factory login with the deployed password |

Live controls reach each declared service over a local `kubectl port-forward`,
with one login attempt per control and account; values read from the cluster
are never printed. Exit code: `0` without failure, `1` when a control fails,
`2` on usage errors. Tests: `bash tests/credentials.test.sh` (needs `jq`, `curl`,
and `python3` for the live part).

## Status

`deploy credentials` is implemented. The other commands (`code secrets|sbom|cve|cra`,
`deploy easm|k8s-cis|passport|nis2`, `gateway`) are still placeholders that only print a message.

## Licence

AGPL-3.0-only, © Quatrain Technologies. Source: https://git.qtrn.io/tycho/tycho-security
