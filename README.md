# network-inventory

Outil en ligne de commande, en Python (bibliothèque standard uniquement), qui inventorie un réseau avec Nmap et détecte ce qui change entre deux scans.
Projet personnel d'apprentissage : **à utiliser uniquement sur son propre réseau ou son propre lab.**

## Objectif

Garder une trace exploitable de ce qui est visible sur un réseau, puis repérer les écarts :

- **inventaire** : machines actives, ports TCP ouverts, produit et version de chaque service, adresses MAC (fichier CSV et rapport Markdown) ;
- **changements entre deux scans** : nouveaux hôtes, hôtes disparus, ports ouverts ou fermés, services dont la version change, adresse IP ou adresse MAC modifiée ;
- **prudence** : refus de scanner autre chose qu'un réseau privé de taille raisonnable, aucune commande passée par un shell, formules de tableur neutralisées dans le CSV, anonymisation pour publier un exemple.

## Architecture

```text
                       ┌──────────────────────── netinv ────────────────────────┐
 python3 -m netinv ──► │ cli.py ─► scan.py ─► Nmap (-sV -oX -) ─► XML            │
                       │             parse.py + model.py ─► objets Scan/Host/Port │
                       │             diff.py ─► changements                       │
                       │             report.py ─► CSV / Markdown                  │
                       │             anonymize.py ─► exemples publiables          │
                       └─────────────────────────────────────────────────────────┘
```

| Fichier | Rôle |
|---|---|
| `netinv/scan.py` | valide les cibles et les ports, construit la commande Nmap sous forme de liste (jamais de shell) et la lance, avec `sudo` si demandé |
| `netinv/parse.py`, `netinv/model.py` | lisent le XML de Nmap et le transforment en objets `Scan`, `Host`, `Port` non modifiables ; ne gardent que les hôtes actifs et les ports ouverts, triés |
| `netinv/diff.py` | compare deux scans (opérations d'ensembles) ; reconnaît par son adresse MAC une machine qui a changé d'adresse IP |
| `netinv/report.py` | écrit le CSV et les rapports Markdown, en neutralisant les bannières (données venues du réseau, donc non fiables) |
| `netinv/anonymize.py` | remplace adresses, noms et MAC par des valeurs réservées à la documentation (RFC 5737, 3849, 7042), avec la même correspondance pour les deux scans d'une comparaison |
| `netinv/cli.py` | commandes `scan`, `report` et `diff` ; codes de sortie 0 / 1 / 2 |
| `tests/` | 161 tests `pytest` : XML fabriqués, Nmap simulé, et 3 tests avec le vrai Nmap sur la boucle locale |
| `demo/fake_banner.py` | faux serveur qui envoie une bannière SSH, pour simuler un changement de version |

Lab : deux machines virtuelles Ubuntu 24.04 (Multipass) sur un réseau privé virtuel. `ctrl` lance l'outil, `target` est un serveur (SSH, nginx, pare-feu UFW). La passerelle de ce réseau, le PC hôte, apparaît aussi dans l'inventaire.

## Utilisation

Prérequis : Python 3, Nmap, et `sudo` pour les adresses MAC (`--sudo`). Testé avec Python 3.12.3, Nmap 7.94SVN, pytest 7.4.4, Ubuntu 24.04.5 LTS.

```bash
python3 -m netinv scan <réseau-du-lab-en-CIDR> --sudo --no-dns -o scans/01-reference.xml
python3 -m netinv report scans/01-reference.xml --csv reports/inventaire.csv --md reports/inventaire.md
python3 -m netinv scan <réseau-du-lab-en-CIDR> --sudo --no-dns -o scans/02.xml
python3 -m netinv diff scans/01-reference.xml scans/02.xml --md reports/changements.md
python3 -m netinv diff scans/01-reference.xml scans/02.xml --exit-code    # code 0 : rien, 1 : changements, 2 : erreur
python3 -m pytest -q
```

Les dossiers `scans/` et `reports/` contiennent des données réelles : ils sont ignorés par Git. Seul `samples/` (anonymisé) est publié.

Garde-fous vérifiés : une adresse publique, un nom de domaine, un réseau plus grand qu'un `/16` ou une cible qui ressemble à une option sont refusés **avant** le lancement de Nmap ; un scan existant n'est jamais écrasé sans `--force`.

## Résultats

Résultats réels obtenus dans le lab. Rapports d'exemple, anonymisés : dossier [`samples/`](samples/).

| Preuve | Résultat |
|---|---|
| Premier scan du réseau (1 000 ports TCP les plus courants, `-sV`) | **3 hôtes actifs, 6 ports ouverts**, 94 s (durée mesurée par Nmap) |
| Changement 1 : un serveur web démarre sur le port 8080 | détecté : « 1 port ouvert », service identifié (`SimpleHTTPServer 0.6`) |
| Changement 2 : `target` est arrêtée, puis redémarrée | détecté : « 1 hôte disparu » avec ses ports ; après retour à l'état initial, **aucun changement** face à la référence, et le port 8080 arrêté apparaît en « port fermé » |
| Changement 3 : la version d'un service change (simulation, faux serveur sur le port 2222) | détecté : « 1 service modifié » (OpenSSH 8.9p1 → 9.6p1) ; scan ciblé en 0,14 s |
| Contre-vérification avec `ndiff` (outil officiel de Nmap) | mêmes changements que l'outil |
| Codes de sortie avec `--exit-code` | 0 (aucun changement), 1 (changements), 2 (fichier introuvable) |
| Tests | **161 réussis** en 2,4 s (`python3 -m pytest -q`) |
| Recherche de fuites dans `samples/` | aucune adresse IP, adresse MAC ou nom de fabricant réels |

## Limites

- Photo d'un instant : une machine éteinte ou occupée pendant le scan apparaît comme « disparue » (faux positif possible).
- IPv4 et TCP seulement ; pas de scan UDP.
- Sans `-p`, Nmap ne regarde que les 1 000 ports TCP les plus courants : dans mon lab, quatre services du PC hôte, ouverts sur des ports peu courants, n'apparaissent pas dans l'inventaire. Un inventaire ne couvre que ce qu'on scanne.
- L'outil ne garde que les ports ouverts : un port fermé et un port filtré par un pare-feu apparaissent tous deux comme « fermés » dans un rapport de changements.
- La détection de version lit ce que le service **annonce** : une bannière peut être masquée ou falsifiée (c'est ce que fait `demo/fake_banner.py`).
- Une machine est reconnue par son adresse IP. Un changement d'adresse n'est détecté que si l'adresse MAC est connue (`--sudo`, même réseau local) et s'il n'y a qu'une machine concernée de chaque côté.
- Les exemples anonymisés gardent les ports, produits et versions (c'est leur intérêt) : l'anonymisation réduit l'information publiée, elle ne la supprime pas.
- Testé uniquement dans ce lab, jamais sur un réseau d'entreprise. Pas de surveillance continue : les scans sont lancés à la main.

## Sécurité et éthique

- À lancer sur ses propres machines uniquement ; l'outil refuse les adresses publiques (sauf `--allow-public`, explicite).
- Nmap est lancé sans shell (commande sous forme de liste) : pas d'injection de commande possible par une cible.
- Les bannières lues sur le réseau sont des données non fiables : le CSV neutralise les formules de tableur (`= + - @`), le Markdown échappe `|`, `<`, `>` et `&`.
- Avec `--sudo`, seul Nmap tourne en root ; le XML revient par la sortie standard et le fichier appartient à l'utilisateur.
- Le XML est lu avec `xml.etree.ElementTree`, qui n'est pas protégé contre un XML malveillant : ne lui donner que ses propres fichiers (pour des fichiers reçus d'ailleurs, il faudrait `defusedxml`).

## Ce que j'ai appris et problèmes rencontrés

- **Une mise à jour automatique a cassé les VM.** Après une coupure de courant, les VM ne démarraient plus (`No route to host`) alors que `multipass list` les disait `Running`. Le journal du service (`journalctl -u snap.multipass.multipassd`) montrait la cause : snap avait mis Multipass à jour en arrière-plan (1.17.0 → 1.17.1), mais chaque VM pointait encore vers le micrologiciel UEFI de l'ancienne révision, et AppArmor en refusait l'accès (`Permission denied`). Correction : `snap revert` vers la révision attendue, puis `snap refresh --hold` jusqu'à la fin du projet.
- **`$!` ne désigne que le dernier processus lancé, même s'il a échoué.** En recollant le bloc de démarrage du serveur 8080, un 2ᵉ serveur a échoué (port déjà pris), mais son numéro de processus a remplacé le bon dans le fichier `.pid` : le `kill` suivant aurait visé un processus inexistant. Retrouvé et corrigé avec `pgrep -f`. Leçon : vérifier qu'un port est libre avant de démarrer un service, et vérifier le processus après.
- **Les ports peu courants sont invisibles sans `-p`.** Le PC hôte écoute sur sept ports ; le scan par défaut n'en a vu que trois.
- **`filtered` n'est pas `closed`.** `target` garde le pare-feu UFW d'un projet précédent : Nmap y voit 998 ports « filtrés » (paquets ignorés) au lieu de « fermés » (connexion refusée). `ndiff` le montre ; l'outil, qui ne garde que les ports ouverts, n'en est pas affecté.
- **`python3 -m netinv` dépend du dossier courant.** Lancé depuis `reports/`, il répond `No module named netinv` : Python cherche le paquet dans le dossier courant.
- **Valider contre une référence.** Comparer la sortie de l'outil avec Nmap lancé directement, puis avec `ndiff`, prouve qu'il donne le bon résultat sur de vrais scans, ce que des tests sur des données fabriquées ne prouvent pas seuls.

## Pour aller plus loin

- Planifier le scan avec `cron` et `diff --exit-code`, et envoyer une alerte quand le code vaut 1.
- Une liste d'hôtes connus (`--known hosts.txt`) pour signaler un appareil inconnu sur le réseau.
- Un filtre `--ignore-port` pour réduire les faux positifs, et un export JSON.
- Lancer `pytest` à chaque `push` (GitHub Actions).
- Prise en charge de l'IPv6.

## Origine

Projet réalisé à partir d'un guide pas à pas de référence, que j'ai suivi, compris puis adapté à mon lab (dépôt sur le PC partagé avec la VM de contrôle, passerelle visible dans l'inventaire, contrôles supplémentaires).
