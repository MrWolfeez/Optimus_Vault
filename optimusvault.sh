#!/bin/bash

# ==============================================
# OPTIMUS VAULT v2 - VERSION PROPRE
# Script pour environnement sécurisé avec GPG
# ==============================================

OPTIMUS_FILE="optimus_vault.img"
OPTIMUS_MAPPER="optimus_vault_mapper"
OPTIMUS_MOUNT="$HOME/.optimus_vault_mount"
LOG_FILE="$HOME/Documents/COURS/LINUXADVANCED/CC1/log/optimus_vault.log"

# ==============================================
# FONCTIONS DE BASE
# ==============================================

function check_dependencies() {
    for cmd in cryptsetup numfmt mkfs.ext4; do
        command -v "$cmd" >/dev/null || {
            echo "[-] $cmd non trouvé"
            exit 1
        }
    done
}

log() {
    echo "[$(date '+%F %T')] $*" >> "$LOG_FILE"
}

function print_status() {
    if [ ! -f "$OPTIMUS_FILE" ]; then
        echo "[INFO] Aucun environnement détecté (fichier $OPTIMUS_FILE manquant)"
    elif sudo cryptsetup status "$OPTIMUS_MAPPER" &>/dev/null; then
        if mountpoint -q "$OPTIMUS_MOUNT"; then
            echo "[INFO] Volume ouvert et monté à $OPTIMUS_MOUNT"
        else
            echo "[INFO] Volume ouvert mais non monté"
        fi
    else
        echo "[INFO] Volume fermé (fichier existant)"
    fi
}

function run() {
    "$@" &
    pid=$!
    while kill -0 $pid 2>/dev/null; do
        printf "."; sleep 0.2
    done
    wait $pid
    return $?
}

# ==============================================
# FONCTIONS PRINCIPALES
# ==============================================

function install_env() {
    echo "[*] Création d'un environnement sécurisé..."
    log "Démarrage de l'installation d'un environnement sécurisé"

    if sudo cryptsetup status "$OPTIMUS_MAPPER" &>/dev/null; then
        echo "[!] Volume déjà mappé. Fermeture automatique..."
        log "Volume déjà mappé, tentative de fermeture"
        sudo umount "$OPTIMUS_MOUNT" &>/dev/null
        sudo cryptsetup luksClose "$OPTIMUS_MAPPER" || {
            echo "[-] Impossible de fermer le volume existant."
            log "Échec lors de la fermeture du volume existant"
            exit 1
        }
        log "Volume fermé avec succès"
    fi

    read -p "Taille de l'environnement (ex : 20M, 1G) : " SIZE
    SIZE=$(echo "$SIZE" | tr '[:lower:]' '[:upper:]')
    read -s -p "Mot de passe : " PASS; echo
    log "Taille choisie : $SIZE"

    BYTES=$(numfmt --from=iec "$SIZE" 2>/dev/null)
    if [[ -z "$BYTES" || ! "$BYTES" =~ ^[0-9]+$ ]]; then
        echo "[-] Taille invalide."
        log "Erreur : taille invalide entrée : $SIZE"
        exit 1
    fi
    COUNT=$((BYTES / 1048576))

    echo -n "[~] Création du fichier image..."
    run dd if=/dev/zero of="$OPTIMUS_FILE" bs=1M count="$COUNT" status=none || {
        echo " Échec"
        log "Échec lors de la création de l'image"
        exit 1
    }; echo " OK"
    log "Image de $COUNT MiB créée"

    TMPKEY=$(mktemp); chmod 600 "$TMPKEY"; echo -n "$PASS" > "$TMPKEY"

    echo -n "[~] Chiffrement..."
    run sudo cryptsetup luksFormat "$OPTIMUS_FILE" --key-file="$TMPKEY" || {
        echo " Échec"; rm -f "$TMPKEY"; log "Échec lors du chiffrement"; exit 1
    }; echo " OK"
    log "Image chiffrée avec succès"

    echo -n "[~] Ouverture..."
    run sudo cryptsetup luksOpen "$OPTIMUS_FILE" "$OPTIMUS_MAPPER" --key-file="$TMPKEY" || {
        echo " Échec"; rm -f "$TMPKEY"; log "Échec à l'ouverture après chiffrement"; exit 1
    }; echo " OK"
    log "Volume ouvert après chiffrement"

    rm -f "$TMPKEY"

    echo -n "[~] Formatage..."
    run sudo mkfs.ext4 /dev/mapper/$OPTIMUS_MAPPER >/dev/null || {
        echo " Échec"; sudo cryptsetup luksClose $OPTIMUS_MAPPER; log "Échec formatage ext4"; exit 1
    }; echo " OK"
    log "Volume formaté en ext4"

    mkdir -p "$OPTIMUS_MOUNT"
    echo -n "[~] Montage..."
    run sudo mount /dev/mapper/$OPTIMUS_MAPPER "$OPTIMUS_MOUNT" || {
        echo " Échec"; sudo cryptsetup luksClose $OPTIMUS_MAPPER; log "Échec du montage"; exit 1
    }; echo " OK"
    log "Montage terminé dans $OPTIMUS_MOUNT"

    # CORRECTION : Donner ownership de tout le point de montage à l'utilisateur
    echo -n "[~] Configuration des permissions..."
    # Utiliser l'ID utilisateur plutôt que le nom pour éviter les problèmes avec les points
    local USER_ID=$(id -u)
    local GROUP_ID=$(id -g)
    sudo chown "$USER_ID:$GROUP_ID" "$OPTIMUS_MOUNT" || {
        echo " Échec ownership"; log "Échec configuration ownership"; exit 1
    }
    echo " OK"
    log "Ownership configuré pour UID:GID $USER_ID:$GROUP_ID"

    # Initialisation structure GPG
    echo -n "[~] Initialisation structure GPG..."
    local GPG_DIR="$OPTIMUS_MOUNT/.gnupg"
    local GPG_EXPORT_DIR="$OPTIMUS_MOUNT/gpg_exports"
    
    sudo mkdir -p "$GPG_DIR" "$GPG_EXPORT_DIR"
    sudo chmod 700 "$GPG_DIR" "$GPG_EXPORT_DIR"
    sudo chown -R "$(whoami):$(whoami)" "$GPG_DIR" "$GPG_EXPORT_DIR"
    echo " OK"
    log "Structure GPG initialisée"

    echo "[+] Environnement prêt : $OPTIMUS_MOUNT"
    log "Installation terminée avec succès"
}

function open_env() {
    read -s -p "Mot de passe : " PASS; echo
    log "Tentative d'ouverture de l'environnement"

    if sudo cryptsetup status "$OPTIMUS_MAPPER" &>/dev/null; then
        echo "[!] Le volume est déjà ouvert."
        log "Volume déjà ouvert, ouverture ignorée"
        return
    fi

    if mountpoint -q "$OPTIMUS_MOUNT"; then
        echo "[!] Volume déjà monté à $OPTIMUS_MOUNT"
        log "Volume déjà monté à $OPTIMUS_MOUNT"
        return
    fi

    TMPKEY=$(mktemp); chmod 600 "$TMPKEY"; echo -n "$PASS" > "$TMPKEY"

    echo -n "[~] Ouverture..."
    run sudo cryptsetup luksOpen "$OPTIMUS_FILE" "$OPTIMUS_MAPPER" --key-file="$TMPKEY" || {
        echo " Échec"; rm -f "$TMPKEY"; log "Échec à l'ouverture du volume"; exit 1
    }; echo " OK"
    log "Volume ouvert avec succès"

    rm -f "$TMPKEY"

    echo -n "[~] Montage..."
    run sudo mount /dev/mapper/$OPTIMUS_MAPPER "$OPTIMUS_MOUNT" || {
        echo " Échec"; sudo cryptsetup luksClose $OPTIMUS_MAPPER; log "Échec montage"; exit 1
    }; echo " OK"
    log "Montage réussi sur $OPTIMUS_MOUNT"

    # CORRECTION : Configuration ownership après montage
    echo -n "[~] Configuration des permissions..."
    # Utiliser l'ID utilisateur plutôt que le nom pour éviter les problèmes avec les points
    local USER_ID=$(id -u)
    local GROUP_ID=$(id -g)
    sudo chown "$USER_ID:$GROUP_ID" "$OPTIMUS_MOUNT" || {
        echo " Échec ownership"; log "Échec configuration ownership"
    }
    echo " OK"
    log "Ownership configuré pour UID:GID $USER_ID:$GROUP_ID"

    echo "[+] Monté : $OPTIMUS_MOUNT"
}

function close_env() {
    echo -n "[~] Démontage..."
    run sudo umount "$OPTIMUS_MOUNT" || {
        echo " Échec"; log "Échec démontage"; exit 1
    }; echo " OK"
    log "Démontage réussi"

    echo -n "[~] Fermeture..."
    run sudo cryptsetup luksClose $OPTIMUS_MAPPER || {
        echo " Échec"; log "Échec fermeture volume"; exit 1
    }; echo " OK"
    log "Fermeture volume réussie"

    echo "[+] Environnement fermé proprement."
}

# ==============================================
# FONCTIONS GPG COMPLÈTES
# ==============================================

function check_gpg_dependencies() {
    for cmd in gpg gpg-agent; do
        command -v "$cmd" >/dev/null || {
            echo "[-] $cmd non trouvé. Installez gnupg."
            read -p "Appuyez sur Entrée pour continuer..."
            return 1
        }
    done
    return 0
}

function auto_gpg_setup() {
    echo "[*] Configuration GPG automatisée..."
    log "Démarrage configuration GPG automatisée"
    
    if ! mountpoint -q "$OPTIMUS_MOUNT"; then
        echo "[-] Environnement non monté. Ouvrez d'abord le coffre."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    check_gpg_dependencies || return 1
    
    local GPG_DIR="$OPTIMUS_MOUNT/.gnupg"
    local GPG_EXPORT_DIR="$OPTIMUS_MOUNT/gpg_exports"
    
    # S'assurer que les permissions sont correctes
    # Utiliser UID:GID pour éviter problème avec nom d'utilisateur contenant un point
    local USER_ID=$(id -u)
    local GROUP_ID=$(id -g)
    
    if [ ! -w "$GPG_DIR" ]; then
        echo "[~] Correction des permissions..."
        sudo chown -R "$USER_ID:$GROUP_ID" "$GPG_DIR" "$GPG_EXPORT_DIR" 2>/dev/null || {
            echo "[-] Impossible de modifier les permissions"
            echo "    Essayez de redémarrer le script en tant qu'administrateur"
            read -p "Appuyez sur Entrée pour continuer..."
            return 1
        }
        chmod 700 "$GPG_DIR" "$GPG_EXPORT_DIR" 2>/dev/null
    fi
    
    # Vérifier que GPG peut écrire dans le répertoire
    if [ ! -w "$GPG_DIR" ]; then
        echo "[-] Problème de permissions sur $GPG_DIR"
        echo "    Propriétaire actuel: $(ls -ld "$GPG_DIR" | awk '{print $3":"$4}')"
        echo "    Utilisateur actuel: $(whoami) (UID:$USER_ID)"
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    echo "=== CONFIGURATION GPG ==="
    read -p "Nom complet : " GPG_NAME
    read -p "Email : " GPG_EMAIL
    read -s -p "Passphrase pour la clé : " GPG_PASS; echo
    echo ""
    
    # Création du fichier batch
    local GPG_BATCH_FILE="$GPG_DIR/batch_config"
    cat > "$GPG_BATCH_FILE" << EOF
%echo Génération d'une clé GPG automatisée
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $GPG_NAME
Name-Email: $GPG_EMAIL
Expire-Date: 2y
Passphrase: $GPG_PASS
%commit
%echo Clé générée avec succès
EOF
    
    echo -n "[~] Génération de la paire de clés..."
    
    # Génération avec GNUPGHOME personnalisé et permissions correctes
    export GNUPGHOME="$GPG_DIR"
    
    # S'assurer que GPG peut créer ses fichiers temporaires
    mkdir -p "$GNUPGHOME"
    chmod 700 "$GNUPGHOME"
    
    # Générer la clé avec gestion d'erreur améliorée
    if ! gpg --batch --generate-key "$GPG_BATCH_FILE" 2>/dev/null; then
        echo " Échec"
        echo ""
        echo "[-] Erreur lors de la génération. Vérifications :"
        echo "    - GNUPGHOME : $GNUPGHOME"
        echo "    - Permissions : $(ls -ld "$GNUPGHOME" 2>/dev/null || echo 'Répertoire introuvable')"
        echo "    - Espace disque disponible :"
        df -h "$OPTIMUS_MOUNT" 2>/dev/null || echo "    Impossible de vérifier l'espace disque"
        
        log "Échec génération clé GPG"
        unset GNUPGHOME
        rm -f "$GPG_BATCH_FILE"
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    echo " OK"
    log "Clé GPG générée : $GPG_EMAIL"
    
    # Export automatique de la clé publique
    echo -n "[~] Export clé publique..."
    gpg --armor --export "$GPG_EMAIL" > "$GPG_EXPORT_DIR/public_key_${GPG_EMAIL}.asc" || {
        echo " Échec"
        log "Échec export clé publique"
        unset GNUPGHOME
        rm -f "$GPG_BATCH_FILE"
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    }
    echo " OK"
    log "Clé publique exportée"
    
    # Proposer export clé privée
    echo ""
    read -p "Exporter la clé privée pour migration ? (y/N) : " EXPORT_PRIVATE
    if [[ "$EXPORT_PRIVATE" =~ ^[Yy]$ ]]; then
        echo -n "[~] Export clé privée (ATTENTION: stockage sécurisé)..."
        gpg --armor --export-secret-keys "$GPG_EMAIL" > "$GPG_EXPORT_DIR/private_key_${GPG_EMAIL}.asc" || {
            echo " Échec"
            log "Échec export clé privée"
        }
        echo " OK"
        chmod 600 "$GPG_EXPORT_DIR/private_key_${GPG_EMAIL}.asc"
        log "Clé privée exportée avec permissions restrictives"
        echo "[!] Clé privée stockée avec permissions 600"
    fi
    
    # Nettoyage du fichier batch (contient la passphrase)
    rm -f "$GPG_BATCH_FILE"
    
    # Affichage résumé
    echo ""
    echo "[+] Configuration GPG terminée !"
    echo "    Clé publique : $GPG_EXPORT_DIR/public_key_${GPG_EMAIL}.asc"
    if [[ "$EXPORT_PRIVATE" =~ ^[Yy]$ ]]; then
        echo "    Clé privée   : $GPG_EXPORT_DIR/private_key_${GPG_EMAIL}.asc"
    fi
    echo "    Keyring      : $GPG_DIR"
    
    unset GNUPGHOME
    echo ""
    read -p "Appuyez sur Entrée pour continuer..."
}

function gpg_menu() {
    clear
    echo "======== GESTION GPG ========"
    echo "1) Configuration automatisée (nouvelle clé)"
    echo "2) Test structure GPG"
    echo "3) Retour au menu principal"
    echo "============================="
    read -p "Choix : " GPG_CHOICE
    
    case "$GPG_CHOICE" in
        1) auto_gpg_setup ;;
        2) simple_gpg_test ;;
        3) return ;;
        *) echo "Choix invalide." ; sleep 1 ;;
    esac
}

function simple_gpg_test() {
    if ! mountpoint -q "$OPTIMUS_MOUNT"; then
        echo "[-] Ouvrez d'abord l'environnement."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    local GPG_DIR="$OPTIMUS_MOUNT/.gnupg"
    local GPG_EXPORT_DIR="$OPTIMUS_MOUNT/gpg_exports"
    
    echo "[INFO] Structure GPG prête :"
    echo "   Keyring: $GPG_DIR"
    echo "   Exports: $GPG_EXPORT_DIR"
    echo ""
    
    if [ -d "$GPG_DIR" ]; then
        echo "   Status: ✅ Répertoires créés"
        echo "   Permissions actuelles :"
        ls -la "$OPTIMUS_MOUNT" | grep -E "(gnupg|gpg_exports)"
        echo ""
        
        # Test des permissions d'écriture
        if [ -w "$GPG_DIR" ]; then
            echo "   ✅ Permissions d'écriture OK"
        else
            echo "   ⚠️  Problème de permissions - correction..."
            # Utiliser UID:GID au lieu du nom d'utilisateur
            local USER_ID=$(id -u)
            local GROUP_ID=$(id -g)
            sudo chown -R "$USER_ID:$GROUP_ID" "$GPG_DIR" "$GPG_EXPORT_DIR"
            echo "   ✅ Permissions corrigées"
        fi
    else
        echo "   Status: ❌ Structure manquante"
    fi
    
    echo ""
    read -p "Appuyez sur Entrée pour continuer..."
}

# ==============================================
# IMPORT/EXPORT GPG (Part IV du partiel)
# ==============================================

function import_gpg_from_vault() {
    echo "[*] Import des clés GPG du coffre vers le trousseau système..."
    log "Import GPG coffre -> système"
    
    if ! mountpoint -q "$OPTIMUS_MOUNT"; then
        echo "[-] Environnement non monté."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    local GPG_DIR="$OPTIMUS_MOUNT/.gnupg"
    
    if [ ! -d "$GPG_DIR" ]; then
        echo "[-] Aucune configuration GPG trouvée dans le coffre."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    echo "=== CLÉS DISPONIBLES DANS LE COFFRE ==="
    export GNUPGHOME="$GPG_DIR"
    
    if ! gpg --list-keys 2>/dev/null | grep -q "pub"; then
        echo "Aucune clé trouvée dans le coffre."
        unset GNUPGHOME
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    gpg --list-keys --with-colons | grep "^pub" | cut -d: -f10
    echo ""
    
    read -p "Importer toutes les clés dans le trousseau système ? (y/N) : " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -n "[~] Import en cours..."
        
        local temp_export=$(mktemp)
        gpg --armor --export > "$temp_export" 2>/dev/null
        gpg --armor --export-secret-keys >> "$temp_export" 2>/dev/null
        
        unset GNUPGHOME
        
        if gpg --import "$temp_export" 2>/dev/null; then
            echo " OK"
            log "Clés importées dans le trousseau système"
            echo "[+] Clés importées dans le trousseau système"
        else
            echo " Échec"
            log "Échec import clés système"
        fi
        
        rm -f "$temp_export"
    fi
    
    unset GNUPGHOME
    echo ""
    read -p "Appuyez sur Entrée pour continuer..."
}

function export_gpg_to_vault() {
    echo "[*] Export des clés GPG du trousseau système vers le coffre..."
    log "Export GPG système -> coffre"
    
    if ! mountpoint -q "$OPTIMUS_MOUNT"; then
        echo "[-] Environnement non monté."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    echo "=== CLÉS SYSTÈME DISPONIBLES ==="
    if ! gpg --list-secret-keys 2>/dev/null | grep -q "sec"; then
        echo "Aucune clé secrète trouvée dans le trousseau système."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    gpg --list-secret-keys --with-colons | grep "^sec" | cut -d: -f10
    echo ""
    
    read -p "Email de la clé à exporter (ou 'all' pour toutes) : " KEY_EMAIL
    
    local GPG_EXPORT_DIR="$OPTIMUS_MOUNT/gpg_exports"
    mkdir -p "$GPG_EXPORT_DIR"
    
    echo -n "[~] Export vers le coffre..."
    
    if [[ "$KEY_EMAIL" == "all" ]]; then
        gpg --armor --export > "$GPG_EXPORT_DIR/system_public_keys.asc" 2>/dev/null
        gpg --armor --export-secret-keys > "$GPG_EXPORT_DIR/system_private_keys.asc" 2>/dev/null
        chmod 600 "$GPG_EXPORT_DIR/system_private_keys.asc"
        echo " OK"
        echo "[+] Toutes les clés exportées vers le coffre"
    else
        if ! gpg --list-secret-keys "$KEY_EMAIL" &>/dev/null; then
            echo " Échec - Clé non trouvée"
            read -p "Appuyez sur Entrée pour continuer..."
            return 1
        fi
        
        gpg --armor --export "$KEY_EMAIL" > "$GPG_EXPORT_DIR/pub_${KEY_EMAIL}.asc" 2>/dev/null
        gpg --armor --export-secret-keys "$KEY_EMAIL" > "$GPG_EXPORT_DIR/sec_${KEY_EMAIL}.asc" 2>/dev/null
        chmod 600 "$GPG_EXPORT_DIR/sec_${KEY_EMAIL}.asc"
        echo " OK"
        echo "[+] Clé $KEY_EMAIL exportée vers le coffre"
    fi
    
    log "Export GPG terminé"
    echo ""
    read -p "Appuyez sur Entrée pour continuer..."
}

# ==============================================
# CONFIGURATION SSH (Part III du partiel)
# ==============================================

function init_ssh_basic() {
    echo "[*] Configuration SSH basique..."
    log "Configuration SSH basique"
    
    if ! mountpoint -q "$OPTIMUS_MOUNT"; then
        echo "[-] Environnement non monté."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    local SSH_DIR="$OPTIMUS_MOUNT/.ssh"
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    
    local SSH_CONFIG="$SSH_DIR/config"
    cat > "$SSH_CONFIG" << 'EOF'
# OPTIMUS VAULT - Configuration SSH Template
Host *
    AddKeysToAgent yes
    IdentitiesOnly yes
    ServerAliveInterval 60

# Exemple configuration
#Host monserveur
#    HostName server.example.com
#    User myuser
#    IdentityFile ~/.ssh/id_rsa_server
EOF
    chmod 600 "$SSH_CONFIG"
    
    echo "[~] Création alias evsh..."
    echo "alias evsh='ssh -F $SSH_CONFIG'" >> ~/.bashrc 2>/dev/null || true
    
    echo "[+] Configuration SSH basique terminée !"
    echo "    Config SSH : $SSH_CONFIG"
    echo "    Alias evsh ajouté à ~/.bashrc"
    echo ""
    read -p "Appuyez sur Entrée pour continuer..."
}

function import_ssh_config() {
    echo "[*] Import configuration SSH existante..."
    log "Import SSH config"
    
    if ! mountpoint -q "$OPTIMUS_MOUNT"; then
        echo "[-] Environnement non monté."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    local USER_SSH_CONFIG="$HOME/.ssh/config"
    local VAULT_SSH_DIR="$OPTIMUS_MOUNT/.ssh"
    
    if [ ! -f "$USER_SSH_CONFIG" ]; then
        echo "[-] Aucun fichier ~/.ssh/config trouvé."
        read -p "Appuyez sur Entrée pour continuer..."
        return 1
    fi
    
    echo "=== HOSTS DÉTECTÉS ==="
    grep "^Host " "$USER_SSH_CONFIG" | grep -v "\*" | cut -d' ' -f2- | nl -w2 -s') '
    echo ""
    
    read -p "Numéro du host à importer (ou 'all' pour tous) : " HOST_CHOICE
    
    mkdir -p "$VAULT_SSH_DIR"
    chmod 700 "$VAULT_SSH_DIR"
    
    if [[ "$HOST_CHOICE" == "all" ]]; then
        echo -n "[~] Import de toute la configuration..."
        cp "$USER_SSH_CONFIG" "$VAULT_SSH_DIR/config" 2>/dev/null
        chmod 600 "$VAULT_SSH_DIR/config"
        echo " OK"
        echo "[+] Configuration complète importée"
    else
        local HOST_NAME=$(grep "^Host " "$USER_SSH_CONFIG" | grep -v "\*" | sed -n "${HOST_CHOICE}p" | cut -d' ' -f2-)
        if [ -n "$HOST_NAME" ]; then
            echo -n "[~] Import de $HOST_NAME..."
            awk "/^Host $HOST_NAME/,/^Host / { if(/^Host / && \$2 != \"$HOST_NAME\") exit; print }" "$USER_SSH_CONFIG" >> "$VAULT_SSH_DIR/config"
            chmod 600 "$VAULT_SSH_DIR/config"
            echo " OK"
            echo "[+] Host $HOST_NAME importé"
        else
            echo "[-] Host non trouvé"
        fi
    fi
    
    log "Import SSH config terminé"
    echo ""
    read -p "Appuyez sur Entrée pour continuer..."
}

# ==============================================
# MENUS ÉTENDUS
# ==============================================

function gpg_menu_extended() {
    clear
    echo "======== GESTION GPG ÉTENDUE ========"
    echo "1) Configuration automatisée (nouvelle clé)"
    echo "2) Test structure GPG"
    echo "3) Import clés (coffre -> système)"
    echo "4) Export clés (système -> coffre)"
    echo "5) Retour au menu principal"
    echo "===================================="
    read -p "Choix : " GPG_CHOICE
    
    case "$GPG_CHOICE" in
        1) auto_gpg_setup ;;
        2) simple_gpg_test ;;
        3) import_gpg_from_vault ;;
        4) export_gpg_to_vault ;;
        5) return ;;
        *) echo "Choix invalide." ; sleep 1 ;;
    esac
}

function ssh_menu_basic() {
    clear
    echo "======== CONFIGURATION SSH ========"
    echo "1) Configuration SSH basique + alias evsh"
    echo "2) Import config SSH existant par host"
    echo "3) Retour au menu principal"
    echo "==================================="
    read -p "Choix : " SSH_CHOICE
    
    case "$SSH_CHOICE" in
        1) init_ssh_basic ;;
        2) import_ssh_config ;;
        3) return ;;
        *) echo "Choix invalide." ; sleep 1 ;;
    esac
}

# ==============================================
# MENU PRINCIPAL
# ==============================================

function menu() {
    clear
    if command -v toilet >/dev/null; then
        toilet -f mono12 -F border --gay "OPTIMUS"
    else
        figlet "OPTIMUS_VAULT" | lolcat 2>/dev/null || figlet "OPTIMUS_VAULT"
    fi

    print_status
    echo "======== ENVIRONNEMENT SÉCURISÉ ========"
    echo "1) Installer (créer + chiffrer + monter)"
    echo "2) Ouvrir l'environnement"
    echo "3) Fermer l'environnement"
    echo "4) Gestion GPG"
    echo "5) Configuration SSH"
    echo "6) Quitter"
    echo "========================================"
    read -p "Choix : " CHOICE

    case "$CHOICE" in
        1) install_env ;;
        2) open_env ;;
        3) close_env ;;
        4) gpg_menu_extended ;;
        5) ssh_menu_basic ;;
        6) echo "Bye." ; log "Script quitté" ; exit 0 ;;
        *) echo "Choix invalide." ;;
    esac
}

# ==============================================
# POINT D'ENTRÉE
# ==============================================

check_dependencies

while true; do
    menu
    echo
done