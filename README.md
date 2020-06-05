# FreeboxOS reboot

Ce script permet de contourner la [perte de lien Internet via mode bridge après reconnexion lien FO (#FS22818)](https://dev.freebox.fr/bugs/task/22818).

Il suffit de l'exécuter via une tâche de cron ou un [timer systemd](https://wiki.archlinux.org/index.php/Systemd/Timers) pour redémarrer
automatiquement la Freebox lorsqu'une perte de lien est détectée.

La tâche :

- Vérifie que la Freebox est disponible
- Effectue un ping vers 8.8.8.8 et 1.1.1.1
- Si les 2 IP ne répondent pas au ping sous une seconde, un reboot de la Freebox est lancé

## Installation

Les seules dépendances sont python3 et le module Requests (```pip3 install requests```, ou ```apt install python3-requests``` sous Debian).

Pour installer le script, lancez les commandes suivantes :

```bash
wget https://raw.githubusercontent.com/ugomeda/freebox-os-reboot/master/freebox-os-reboot.py
chmod +x freebox-os-reboot.py
./freebox-os-reboot.py register
```

Puis suivez les instructions. Il suffit ensuite de configurer une tâche qui apelle le script sans paramètre.

## Usage

```
usage: freebox-os-reboot.py [-h] {register,verify,reboot,check} ...

Outil pour redémarrer la Freebox lorsqu'une déconnexion est détectée.

optional arguments:
  -h, --help            show this help message and exit

Commandes:
  {register,verify,reboot,check}
    register            Enregistre l'application sur FreeboxOS
    verify              Vérifie la configuration du script
    reboot              Redémarre la Freebox
    check               Vérifie l'accès à internet et redémarre la Freebox si
                        nécessaire
```
