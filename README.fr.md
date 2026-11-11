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
tycho security deploy credentials   # identifiants d'usine (statique ; --live sur un cluster)
tycho security deploy easm <domain> # surface d'attaque externe : DNSSEC, TLS, CSP
tycho security deploy k8s-cis       # benchmark CIS Kubernetes et contextes de sécurité
tycho security deploy passport      # Tycho Trust Passport signé (NIS 2 / ISO 27001)
tycho security deploy nis2          # contrôles de l'article 21 de NIS 2

# Passerelle zero-trust
tycho security gateway              # passerelle pour agents LLM et coffre de secrets en mémoire

tycho sec code secrets              # mêmes commandes via l'alias court
```

Sans domaine ni action, le module affiche son aide.

## Audit des identifiants d'usine

`tycho security deploy credentials` met en œuvre les contrôles de la fiche
*Factory Default Credentials* (AGENTS.okf, `content/cybersecurity/factory-default-credentials.md`).
Il lit le descripteur d'un fournisseur de recettes : `.tycho/repository.json`
(variables) et `.tycho/recipes/<engine>/<recipe>/package.json`, champ `tycho.credentials`.

```bash
tycho security deploy credentials --recipes <dépôt-fournisseur>          # contrôles statiques
tycho security deploy credentials --recipes <dépôt-fournisseur> --live \
    --context <contexte-kubectl>                                          # + contrôles en direct
tycho security deploy credentials --recipe <nom> --format json           # une recette, rapport JSON
```

| Contrôle | Type | Échoue quand |
| :--- | :--- | :--- |
| `credentials.declared` | statique | la recette ne déclare pas ses comptes d'usine (`[]` s'il n'y en a pas) |
| `credentials.login-replaced` | statique | le login d'usine est conservé : pas de variable de login, une valeur par défaut ou un exemple bien connu |
| `credentials.secret-sourced` | statique | une variable de login ou de mot de passe n'est pas un secret obligatoire sans défaut |
| `credentials.exposure-order` | statique | la route publique n'est pas publiée après le remplacement |
| `credentials.factory-rejected` | en direct | le service accepte le couple d'usine |
| `credentials.factory-login-retired` | en direct | le service accepte le login d'usine avec le mot de passe déployé |

Les contrôles en direct joignent chaque service déclaré par un `kubectl port-forward`
local, avec une seule tentative de connexion par contrôle et par compte ; les
valeurs lues dans le cluster ne sont jamais affichées. Code de sortie : `0` sans
échec, `1` si un contrôle échoue, `2` en cas d'erreur d'usage. Tests :
`bash tests/credentials.test.sh` (nécessite `jq`, `curl`, et `python3` pour la partie en direct).

## Statut

`deploy credentials` est implémenté. Les autres commandes (`code secrets|sbom|cve|cra`,
`deploy easm|k8s-cis|passport|nis2`, `gateway`) restent des emplacements réservés
qui affichent seulement un message.

## Licence

AGPL-3.0-only, © Quatrain Technologies. Source : https://git.qtrn.io/tycho/tycho-security
