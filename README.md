# Veille

Petit espace privé pour déposer des PDF et les télécharger.

## Démarrer

Python 3.9 ou plus récent suffit, aucune dépendance à installer.

```sh
export VEILLE_PASSWORD='un-mot-de-passe-a-partager'
python3 veille.py
```

Ouvrir http://127.0.0.1:8000. Les fichiers sont enregistrés dans le dossier
`documents` ; un autre emplacement peut être défini avec `VEILLE_STORAGE_DIR`.
Le serveur accepte les PDF jusqu'à 20 Mo.

Pour que votre collègue puisse y accéder, lancez le serveur sur une adresse
accessible depuis son réseau, par exemple `python3 veille.py --host 0.0.0.0`,
puis communiquez-lui l'adresse et le mot de passe. N'exposez pas le serveur
directement sur Internet : utilisez un réseau privé et HTTPS via un proxy
inverse si un accès depuis Internet est nécessaire.

## Tests

```sh
python3 -m unittest
```
