# Script de scan de ports.
# @LuigiVeau
# Tous droits réservés

from scapy.all import *
import sys
import argparse
import ipaddress

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
### Fonctions de scan

#Fonction de scan d'une IP
def port_scanner(ip, ports, scan_type):
    ### Vérifier si le type de scan est TCP
    if scan_type == "tcp":
        # Création d'un paquet TCP
        print("Lancement du scan TCP :")
        for port in ports:
            pkt = IP(dst=ip)/TCP(dport=int(port), flags="S")
            # On envoie le paquet et on attends la réponse
            response = sr1(pkt, timeout=1, verbose=0)
            # Si une réponse est reçue, on vérifie le flag RST ou ACK
            if response is not None:
                if response.haslayer(TCP) and (response.getlayer(TCP).flags == 0x12 or response.getlayer(TCP).flags == 0x14):
                    print(f"[TCP] - Le port {port} de l'adresse {ip} est : Ouvert")
                else:
                    print(f"[TCP] - Le port {port} de l'adresse {ip} est : Fermé (pas de flag ACK ou RST)")
            else:
                print(f"[TCP] - Le port {port} de l'adresse {ip} ne réponds pas.")

    ### Vérifier si le type de scan est UDP
    elif scan_type == "udp":
        ## Création d'un paquet UDP
        print("Lancement du scan UDP :")
        for port in ports:
            pkt = IP(dst=ip)/UDP(dport=int(port))/Raw(b"Salut UDP !")
            # On envoie le paquet et on attends la réponse
            response = sr1(pkt, timeout=1, verbose=0)
            # On vérifie si une réponse est reçue
            if response is not None:
                # Condition de flags
                if response.haslayer(UDP):
                    print(f"[UDP] - Le port {port} de l'adresse {ip} est : Ouvert")
                else:
                    print(f"[UDP] - Le port {port} de l'adresse {ip} est : Fermé (pas de réponse UDP)")

            else:
                # Si pas de réponse. Le port est fermé
                print(f"[UDP] - Le port {port} ne réponds pas.")

    ### Vérifier si le type de scan est PING
    elif scan_type == "ping":
        ## Création d'un paquet ICMP
        print("Lancement d'un ping :")
        pkt = IP(dst=ip)/ICMP()
        # On envoie le paquet et on attends la réponse
        response = sr1(pkt, timeout=1, verbose=0)
        # On vérifie si une réponse est reçue
        if response is not None and response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
            print(f"[PING] - L'adresse {ip} est : UP")
        else:
            print(f"[PING] - L'adresse {ip} est : DOWN")

    ### Vérifier si le type de scan est SYN
    elif scan_type == "syn":
        ## Création d'un paquet TCP SYN
        print("Lancement du scan SYN :")
        for port in ports:
            pkt = IP(dst=ip)/TCP(dport=int(port), flags="S")
            # On envoie le paquet et on attends la réponse
            response = sr1(pkt, timeout=1, verbose=0)
            # Si une réponse est reçue, on vérifie le flag RST ou SYN-ACK
            if response is not None:
                # ... On vérifie si le flag de l'en-tête est à 12 (SYN-ACK) et l'on en déduit qu'il est ouvert
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                    print(f"[SYN] - Le port {port} de l'adresse {ip} est : Ouvert")
                # ... On vérifie si le flag de l'en-tête est à 14 (RST) et l'on en déduit qu'il est fermé
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                    print(f"[SYN] - Le port {port} de l'adresse {ip} est : Fermé")
                else:
                    # Sinon on en déduit qu'il est filtré
                    print(f"[SYN] - Le port {port} de l'adresse {ip} est : Filtré")
            else:
                # Si pas de réponse, le port ne réponds pas.
                print(f"[SYN] - Le port {port} de l'adresse {ip} ne réponds pas.")

    ### Vérifie si le type de scan est TCP FIN
    elif scan_type == "fin":
        ## Création d'un paquet TCP FIN
        print("Lancement du scan FIN :")
        for port in ports:
            pkt = IP(dst=ip)/TCP(dport=int(port), flags="F")
            # On envoie le paquet et on attends la réponse
            response = sr1(pkt, timeout=1, verbose=0)
            # Si une réponse est reçue, on vérifie le flag RST
            if response != None:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                    print(f"[FIN] - Le port {port} de l'adresse {ip} est : Fermé")
                else:
                    print(f"[FIN] - Le port {port} de l'adresse {ip} est : Filtré")
            else:
                print(f"[FIN] - Le port {port} de l'adresse {ip} ne réponds pas.")
                
    else:
        # Si le paquet n'est pas de type TCP, UDP ou SYN, c'est que le type de scan n'est pas pris en charge.
        print("Type de scan non pris en charge. Veuillez spécifier 'tcp' pour un scan TCP, 'udp' pour un scan UDP ou 'syn' pour un SynScan.")

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------
### Parseur d'arguments ###

# Créez un parseur d'arguments. Ca va nous permettre de rajouter des arguments lors de l'exécution de notre script.
parser = argparse.ArgumentParser(description="Scanneur de ports avec Scapy")

# Ajoutez les arguments
parser.add_argument("-t", "--target", help="Adresse IP cible ou réseau CIDR", required=True) # Argument -t pour la cible IP (obligatoire)
parser.add_argument("-p", "--port", help="Port cible", required=False) # Argument -p pour le port cible. (Obligatoire, sauf pour le ping)
parser.add_argument("-s", "--scan", help="Type de scan (tcp,udp,syn,ping)", required=True) #Argument -s pour le type de scan. (Obligatoire)
# Pas pu terminer : parser.add_argument("-o", "--output", help="Fichier de sortie", default=None) # Argument -o pour la sortie des résultats dans un fichier (inexistant par défaut)

# Parsez les arguments
args = parser.parse_args()

# Traitement spécifique de l'argument p (port individuel ou range)
ports = [] # On définit une liste vide
if args.port: # Vérifiez si args.port n'est pas None
    if "-" in args.port: # Si il y a "-" entre 2 ports
        # Range de ports spécifié
        start_port, end_port = map(int, args.port.split("-"))
        ports = range(start_port, end_port+1)
    else:
        # Sinon ce sont des ports individuels que l'on spécifie, séparés par des virgules.
        ports = [int(p) for p in args.port.split(",")]
else:
    # Si aucun port n'est spécifié, on utilise tous les ports (1-65535)
    ports = range(1, 65536)

# Vérification de la validité des arguments
if args.scan.lower() != "ping" and not ports:
    print("Veuillez spécifier au moins un port cible pour un scan de port.")
    sys.exit()

# Vérification de l'adresse IP ou du réseau CIDR
try:
    # Si l'adresse est au format CIDR, on extrait le réseau et le masque
    if "/" in args.target:
        network, mask = args.target.split("/")
        mask = int(mask)
        network = ipaddress.IPv4Network(network + "/" + str(mask), False)
    else:
        # Sinon, on considère que c'est une adresse IP individuelle
        network = ipaddress.IPv4Network(args.target + "/32", False)

    # Boucle sur toutes les adresses IP du réseau
    for ip in network:
        # Appelez la fonction port_scanner avec les arguments
        port_scanner(str(ip), ports, args.scan)

except ipaddress.AddressValueError:
    # Si l'adresse n'est pas valide, on affiche un message d'erreur et on quitte le programme
    print("Adresse IP ou réseau CIDR invalide.")
    sys.exit()
