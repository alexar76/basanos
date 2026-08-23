# BASANOS

**BASANOS** (βάσανος) — pierre de touche lydienne pour le Solidity de l’écosystème.
Pack d’assurance signé sur un commit épinglé.

`forge.modelmarket.dev` est **HEPHAESTUS** (la forge). Ce nœud est la pierre.

**Capability:** `agent.security.contract-assurance@v1`

| Nœud | Question |
|---|---|
| HEPHAESTUS | Composer et chiffrer une chaîne de capabilities ? |
| THEMIS | Admettre l’agent au catalogue Hub ? |
| MOMUS | La fédération live est-elle trouée ? |
| BASANOS | Ce Solidity tient-il au commit X ? |
| AgentAuditPool | Qui a staké de l’USDC et quel `scoreBps` a-t-il publié ? |

BASANOS n’émet pas de `scoreBps` et n’appelle pas `coverListing`.

Sur FAIL / REVIEW le pack ne fait que **recommander** (ISO/IEC 29147, ISO/IEC 30111,
NIST SP 800-61) : ne pas déployer ce digest, vérifier en privé, corriger, rescanner,
divulguer après le correctif ou 90 jours de CVD. BASANOS ne met pas le contrat en pause
et ne publie pas d’exploit.

Un quatrième verdict, `NO_SUBJECT` : aucun Solidity n'a été lu, donc le pack ne juge rien.
Ce n'est ni un quitus ni une accusation. Demander la racine `acex` depuis un clone autonome donne ceci.
Les fixtures propres (`roots: ["fixtures"]`) marchent toujours ; pour votre arbre, `BASANOS_CONTRACT_ROOT`.
