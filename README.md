# ⚡ Suivi de ma consommation électrique

Chaque matin, GitHub récupère les données de mon compteur Linky (via [Conso API](https://conso.boris.sh))
et met à jour une page web consultable sur téléphone. Les données sont **chiffrées** : sans le mot de passe,
la page et le fichier `docs/donnees.chiffre` ne montrent rien de lisible.

## Réglages
- Prix, plages d'heures creuses, abonnement : fichier `config.json`.
- Secrets (Settings > Secrets and variables > Actions) : `LINKY_PRM`, `LINKY_JETON`, `MOT_DE_PASSE_PAGE`.
- Lancer une mise à jour à la main : onglet **Actions** > « Mise à jour quotidienne Linky » > **Run workflow**.
