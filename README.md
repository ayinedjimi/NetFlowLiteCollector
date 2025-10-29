# 🚀 NetFlowLiteCollector


**Développé par: Ayi NEDJIMI Consultants**

## 📋 Description

NetFlowLiteCollector est un collecteur léger de données NetFlow et sFlow pour l'analyse court terme du trafic réseau. Il reçoit des datagrammes UDP NetFlow/sFlow, agrège les flows par paire source/destination, et affiche les top talkers (connexions générant le plus de trafic).

NetFlow est un protocole développé par Cisco pour la collecte et l'analyse du trafic réseau. Il permet de :
- Identifier les sources de trafic réseau
- Détecter les anomalies de bande passante
- Analyser les patterns de communication
- Détecter les exfiltrations de données
- Monitorer les performances réseau

Cet outil est conçu pour une utilisation lightweight et court terme, sans persistance en base de données.


## 📌 Prérequis

- Windows 10/11 ou Windows Server 2016+
- Visual Studio 2019+ avec Build Tools (cl.exe)
- Source de données NetFlow/sFlow (routeur, switch, ou générateur de test)
- Firewall configuré pour autoriser le port UDP (par défaut 2055)


## Compilation

### Option 1 : Utiliser le script batch
```batch
go.bat
```

### Option 2 : Ligne de commande manuelle
```batch
cl.exe /EHsc /W4 /std:c++17 /Fe:NetFlowLiteCollector.exe NetFlowLiteCollector.cpp /link ws2_32.lib comctl32.lib user32.lib gdi32.lib
```


## 🚀 Utilisation

1. Lancer l'exécutable `NetFlowLiteCollector.exe`
2. Entrer le port UDP (par défaut 2055 pour NetFlow)
3. Cliquer sur **Démarrer**
4. Observer les flows s'afficher en temps réel
5. Cliquer sur **Arrêter** pour stopper la collecte
6. Optionnel : Exporter les résultats en CSV


## Interface

### Champ de saisie
- **Port UDP** : Port d'écoute pour les datagrammes NetFlow/sFlow (défaut : 2055)

### Boutons
- **Démarrer** : Lance l'écoute UDP et la collecte de flows
- **Arrêter** : Arrête la collecte
- **Exporter CSV** : Exporte les flows agrégés au format CSV UTF-8 avec BOM

### Liste des résultats (Top Talkers)
Colonnes affichées (triées par bytes décroissant) :
- **SrcIP** : Adresse IP source
- **DstIP** : Adresse IP destination
- **Packets** : Nombre total de paquets agrégés
- **Bytes** : Nombre total d'octets agrégés (critère de tri)
- **Protocol** : Protocole IP (TCP, UDP, ICMP, etc.)
- **FirstSeen** : Heure de première observation du flow (HH:MM:SS)
- **LastSeen** : Heure de dernière observation du flow (HH:MM:SS)

**Note** : La liste affiche les top 1000 flows maximum. Rafraîchissement toutes les 2 secondes.

### Barre de statut
Affiche l'état actuel de la collecte et le nombre de flows uniques agrégés.


## Protocole NetFlow

### NetFlow v5
Format standard de Cisco, le plus répandu.

**Structure du paquet NetFlow v5** :
- **Header (24 bytes)** :
  - Version : 5 (2 bytes)
  - Count : Nombre de flows dans le paquet (2 bytes)
  - SysUptime : Temps depuis le démarrage (4 bytes)
  - Unix_secs : Timestamp Unix (4 bytes)
  - Unix_nsecs : Nanosecondes (4 bytes)
  - Flow_sequence : Numéro de séquence (4 bytes)
  - Engine_type/ID : Type et ID du moteur (2 bytes)
  - Sampling_interval : Intervalle d'échantillonnage (2 bytes)

- **Flow Record (48 bytes chacun, max 30 par paquet)** :
  - srcaddr : IP source (4 bytes)
  - dstaddr : IP destination (4 bytes)
  - nexthop : Next hop router IP (4 bytes)
  - input : Index interface entrée (2 bytes)
  - output : Index interface sortie (2 bytes)
  - dPkts : Nombre de paquets (4 bytes)
  - dOctets : Nombre d'octets (4 bytes)
  - First : Timestamp premier paquet (4 bytes)
  - Last : Timestamp dernier paquet (4 bytes)
  - srcport : Port source (2 bytes)
  - dstport : Port destination (2 bytes)
  - pad1 : Padding (1 byte)
  - tcp_flags : Flags TCP (1 byte)
  - prot : Protocole IP (1 byte)
  - tos : Type of Service (1 byte)
  - src_as : AS source (2 bytes)
  - dst_as : AS destination (2 bytes)
  - src_mask : Masque réseau source (1 byte)
  - dst_mask : Masque réseau destination (1 byte)
  - pad2 : Padding (2 bytes)

### NetFlow v9
Format flexible utilisant des templates.

**Structure** :
- **Header (20 bytes)**
- **FlowSets** (taille variable) :
  - Template FlowSet (ID 0) : Définition des champs
  - Data FlowSet (ID > 255) : Données des flows

**Limitation** : Cet outil détecte NetFlow v9 mais ne le parse pas complètement (parsing complexe nécessitant gestion des templates).

### Ports standards
- **NetFlow** : UDP 2055 (standard), parfois 9996
- **sFlow** : UDP 6343
- **IPFIX (NetFlow v10)** : UDP 4739


## Agrégation des flows

L'outil agrège les flows par **clé unique** composée de :
- IP source
- IP destination
- Protocole IP

Les flows identiques (même clé) sont agrégés :
- Paquets cumulés
- Octets cumulés
- FirstSeen conservé
- LastSeen mis à jour

**Exemple** :
```
Flow 1: 192.168.1.10 -> 8.8.8.8 (TCP) : 100 packets, 50 KB
Flow 2: 192.168.1.10 -> 8.8.8.8 (TCP) : 200 packets, 100 KB
Résultat agrégé: 300 packets, 150 KB
```


## ⚙️ Configuration de l'exportateur NetFlow

Pour envoyer des données à cet outil, configurez votre équipement réseau :

### Cisco IOS
```
ip flow-export version 5
ip flow-export destination <IP_COLLECTEUR> 2055
interface GigabitEthernet0/1
 ip flow ingress
 ip flow egress
```

### Cisco IOS-XR
```
flow exporter-map EXPORTER
 version v9
 transport udp 2055
 destination <IP_COLLECTEUR>
!
flow monitor-map MONITOR
 exporter EXPORTER
 record ipv4
!
interface GigabitEthernet0/0/0/0
 flow ipv4 monitor MONITOR ingress
```

### Linux (softflowd)
```bash
softflowd -i eth0 -n <IP_COLLECTEUR>:2055 -v 5
```

### Windows (nProbe)
```batch
nprobe -i <INTERFACE> -n <IP_COLLECTEUR>:2055
```


## Environnement LAB-CONTROLLED

**AVERTISSEMENT CRITIQUE** : Cet outil est exclusivement destiné à un usage dans des environnements de laboratoire contrôlés.

### Utilisations légitimes
- Analyse de trafic réseau autorisée sur vos propres réseaux
- Tests de performances réseau
- Détection d'anomalies de bande passante
- Formation en analyse NetFlow
- Développement et tests d'outils de monitoring

### INTERDICTIONS STRICTES
- Collecter des flows NetFlow sans autorisation
- Analyser le trafic de réseaux non autorisés
- Utiliser pour l'espionnage ou l'interception de communications
- Exfiltrer les données collectées vers des tiers

### Respect de la vie privée
Les flows NetFlow contiennent des **métadonnées de connexion** :
- IP source/destination
- Ports source/destination
- Volumes de données

Bien que NetFlow ne capture PAS le contenu des paquets, ces métadonnées peuvent révéler :
- Habitudes de navigation (IP destination)
- Applications utilisées (ports)
- Volumes de transfert de fichiers

**Toujours obtenir le consentement des utilisateurs avant de monitorer le trafic réseau.**


# 🚀 Générer des flows de test

## Logs

Les logs sont enregistrés dans :
```
%TEMP%\WinTools_NetFlowLiteCollector_log.txt
```

Les logs contiennent :
- Horodatage de chaque opération
- Démarrage/arrêt de l'écoute
- Port configuré
- Erreurs de socket
- Détection de paquets NetFlow v9
- Opérations d'export


## Limitations

- **Mémoire** : Stockage en RAM uniquement (pas de persistance)
- **Agrégation** : Par paire src/dst/proto uniquement (pas de ports)
- **NetFlow v9** : Détection seulement, parsing incomplet (pas de gestion de templates)
- **IPFIX** : Non supporté
- **sFlow** : Non supporté (détection possible en ajoutant le parser)
- **Affichage** : Top 1000 flows maximum dans la ListView
- **Performances** : Adapté pour monitoring court terme, pas pour analyse longue durée
- **IPv6** : Non supporté (IPv4 uniquement)


## 🚀 Cas d'usage

### 1. Identifier les top talkers
Identifier les sources générant le plus de trafic sur le réseau.

**Exemple** :
```
SrcIP          | DstIP         | Bytes      | Protocol
192.168.1.100  | 8.8.8.8       | 500 MB     | TCP
10.0.0.50      | 20.20.20.20   | 300 MB     | UDP
```

### 2. Détecter les exfiltrations de données
Identifier les transferts de volumes inhabituels vers des IPs externes.

**Indicateurs** :
- Volumes élevés vers des IPs inconnues
- Trafic sortant vers des ports non standards
- Transferts durant les heures non ouvrées

### 3. Analyser les patterns de communication
Identifier les serveurs les plus sollicités.

**Exemple** :
- Serveur web : Nombreuses connexions entrantes sur port 443
- Base de données : Trafic interne constant

### 4. Diagnostiquer les problèmes de performance
Identifier les goulets d'étranglement réseau.

**Exemple** :
- Un serveur génère un trafic anormal (boucle, bug)
- Une application consomme toute la bande passante


## 🔒 Sécurité et Éthique

### Responsabilités de l'utilisateur

1. **Autorisation** : Obtenir une autorisation écrite avant de collecter des flows
2. **Confidentialité** : Ne pas divulguer les patterns de trafic découverts
3. **Législation** : Respecter le RGPD et les lois locales sur la vie privée
4. **Consentement** : Informer les utilisateurs du monitoring réseau
5. **Sécurisation** : Protéger les données collectées (chiffrement, accès restreint)

### Bonnes pratiques

1. **Sécurisation de l'écoute** :
   - Bind uniquement sur localhost si collecte locale
   - Utiliser un firewall pour restreindre les sources NetFlow autorisées
   - Ne pas exposer le collecteur sur Internet

2. **Anonymisation** :
   - Anonymiser les IP internes avant export
   - Agréger les données pour éviter l'identification d'utilisateurs individuels

3. **Rétention** :
   - Définir une politique de rétention des données
   - Supprimer les flows après analyse
   - Ne pas stocker les données indéfiniment

4. **Alerting** :
   - Configurer des alertes pour volumes anormaux
   - Notifier les équipes de sécurité en cas de détection d'anomalie

### Clause de non-responsabilité

L'auteur (Ayi NEDJIMI Consultants) et les contributeurs de cet outil déclinent toute responsabilité concernant :
- Les dommages directs ou indirects résultant de l'utilisation de cet outil
- Les utilisations illégales ou non éthiques
- Les violations de la vie privée
- Les pertes de données ou interruptions de service

**L'utilisateur assume l'entière responsabilité légale et éthique de l'utilisation de ce logiciel.**


## Support

Pour toute question ou problème :
- Consulter les logs dans %TEMP%\WinTools_NetFlowLiteCollector_log.txt
- Vérifier que le port UDP est ouvert (firewall)
- Vérifier que l'exportateur NetFlow est configuré correctement
- Utiliser Wireshark pour capturer les paquets UDP sur le port 2055

### Tester avec nProbe
```batch
nprobe -i <INTERFACE> -n 127.0.0.1:2055 -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %PROTOCOL %IN_BYTES %IN_PKTS"
```


## 📄 Licence

Cet outil est fourni "TEL QUEL", sans garantie d'aucune sorte.

**Usage éducatif et professionnel uniquement dans des environnements autorisés.**

- --

**Ayi NEDJIMI Consultants - 2025**


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>