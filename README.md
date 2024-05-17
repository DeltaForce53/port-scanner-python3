# port-scanner-python3
Un scanneur de Port en Python 3 utilisant la librairie Scapy.
---

## Prérequis

- Python3
- Pip

Installer Python 3 et Pip :

```bash
apt-get install python3 python3-pip
```

## Utilisation

Scanner un réseau :
```bash
python3 scan.py -t réseau/cidr -p port -s service (tcp,udp,ping,syn,fin)
```

Scanner une adresse :
```bash
python3 scan.py -t adresse -p port -s service (tcp,udp,ping,syn,fin)
```
