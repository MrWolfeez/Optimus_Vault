#!/bin/bash

OPTIMUS_FILE="optimus_vault.img"
OPTIMUS_MAPPER="optimus_vault_mapper"
OPTIMUS_MOUNT="$HOME/.optimus_vault_mount"
LOG_FILE="$HOME/Documents/COURS/LINUXADVANCED/CC1/log/optimus_vault.log"

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

    read -p "Taille de l’environnement (ex : 20M, 1G) : " SIZE
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
    echo "4) Quitter"
    echo "========================================"
    read -p "Choix : " CHOICE

    case "$CHOICE" in
        1) install_env ;;
        2) open_env ;;
        3) close_env ;;
        4) echo "Bye." ; log "Script quitté" ; exit 0 ;;
        *) echo "Choix invalide." ;;
    esac
}

check_dependencies

while true; do
    menu
    echo
done
