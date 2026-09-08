#!/bin/bash
# Script de réponse automatique aux intrusions détectées par Suricata
LOGFILE="/var/log/suricata/eve.json"
BLOCKED_LOG="/var/log/suricata/blocked_ips.log"

echo "[+] Démarrage de la surveillance des intrusions... $(date)"

sudo tail -Fn0 "$LOGFILE" | while read -r line; do
    # Ne traiter que les alertes de nos règles personnalisées (sid 1000001-1000005)
    if echo "$line" | grep -qE '"signature_id":100000[1-5]'; then
        SRC_IP=$(echo "$line" | grep -oP '"src_ip":"\K[^"]+')
        SIGNATURE=$(echo "$line" | grep -oP '"signature":"\K[^"]+')

        if [ -n "$SRC_IP" ]; then
            # Vérifie si l'IP n'est pas déjà bloquée
            if ! sudo iptables -L INPUT -n | grep -q "$SRC_IP"; then
                echo "[ALERTE] $(date) - $SIGNATURE depuis $SRC_IP -> BLOCAGE"
                sudo iptables -A INPUT -s "$SRC_IP" -j DROP
                echo "$(date) - BLOQUÉ: $SRC_IP - $SIGNATURE" >> "$BLOCKED_LOG"
            fi
        fi
    fi
done
