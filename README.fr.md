> 🇬🇧 [English version](README.md)

# Tycho Security

`@tycho/security` est le module Tycho derrière `tycho security`, avec l'alias court `tycho sec`. Il a pour but d'auditer le code (secrets, SBOM, CVE, Cyber Resilience Act) et les déploiements (surface d'attaque externe, posture CIS Kubernetes, NIS 2), et de fournir une passerelle zero-trust pour les agents IA. Pour la vue d'ensemble, voir le [README du cœur Tycho](https://git.qtrn.io/tycho/tycho).

## Installation

```bash
tycho module add security
```

## Utilisation

```bash
# Audit de code
tycho security code secrets         # rechercher des secrets divulgués dans l'historique Git
tycho security code sbom            # extraire un SBOM CycloneDX
tycho security code cve             # confronter les dépendances aux CVE connues
tycho security code cra             # vérifier la conformité au Cyber Resilience Act

# Audit de déploiement (alias : runtime)
tycho security deploy easm <domain> # surface d'attaque externe : DNSSEC, TLS, CSP
tycho security deploy k8s-cis       # benchmark CIS Kubernetes et contextes de sécurité
tycho security deploy passport      # Tycho Trust Passport signé (NIS 2 / ISO 27001)
tycho security deploy nis2          # contrôles de l'article 21 de NIS 2

# Passerelle zero-trust
tycho security gateway              # passerelle pour agents LLM et coffre de secrets en mémoire

tycho sec code secrets              # mêmes commandes via l'alias court
```

Sans domaine ni action, le module affiche son aide.

## Statut

Squelette précoce. Toutes les commandes ci-dessus (`code secrets|sbom|cve|cra`, `deploy easm|k8s-cis|passport|nis2`, `gateway`) sont des emplacements réservés qui affichent seulement un message ; aucun scan ni audit n'est encore effectué.

## Licence

AGPL-3.0-only, © Quatrain Technologies. Source : https://git.qtrn.io/tycho/tycho-security
