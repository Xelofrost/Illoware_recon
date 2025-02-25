#!/bin/bash

# Manejo de interrupción (CTRL+C) para salir de inmediato
trap 'echo -e "\n🛑 Script interrumpido. Saliendo..."; exit 1' SIGINT

# Verificar si se proporciona el parámetro correcto
if [ "$#" -ne 1 ]; then
    echo "Uso: $0 <RANGO_CIDR>"
    echo "Ejemplo: $0 172.233.0.0/16"
    exit 1
fi

RANGO_CIDR=$1
OUTPUT_DIR="capturas"

# Crear directorio de salida si no existe
mkdir -p "$OUTPUT_DIR"

# Generar lista de IPs y procesarlas (usando process substitution para heredar la trap)
while read -r IP || [[ -n "$IP" ]]; do
    echo "🔍 Comprobando IP: $IP"

    # Verificar si el host responde al ping
    if ! ping -c 1 -W 1 "$IP" &>/dev/null; then
        echo "❌ $IP no responde al ping. Omitiendo..."
        continue
    fi

    # Verificar si hay un servidor web en HTTP o HTTPS
    if nc -z -w 1 "$IP" 80; then
        PROTO="http"
    elif nc -z -w 1 "$IP" 443; then
        # Verificar si HTTPS responde correctamente (aunque sea con certificado inválido)
        if ! HTTP_STATUS=$(curl -k --silent --fail --max-time 2 --write-out "%{http_code}" --output /dev/null "https://$IP"); then
            echo "⚠️ SSL handshake fallido o error en HTTPS para $IP. Omitiendo..."
            continue
        fi
        
        if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -lt 400 ]]; then
            PROTO="https"
        else
            echo "⚠️ Error HTTP $HTTP_STATUS en HTTPS para $IP. Omitiendo..."
            continue
        fi
    else
        echo "❌ No hay servidor web en $IP. Omitiendo..."
        continue
    fi

    # Verificación final antes de capturar
    if ! HTTP_STATUS=$(curl -k --silent --fail --max-time 2 --write-out "%{http_code}" --output /dev/null "$PROTO://$IP"); then
        echo "⚠️ Error de conexión en $PROTO://$IP. Omitiendo..."
        continue
    fi
    
    if [[ "$HTTP_STATUS" -lt 200 || "$HTTP_STATUS" -ge 400 ]]; then
        echo "⚠️ Error HTTP $HTTP_STATUS en $PROTO://$IP. Omitiendo..."
        continue
    fi

    echo "✅ Servidor OK en $PROTO://$IP (HTTP $HTTP_STATUS). Capturando..."

    # Capturar la página con cutycapt (modo seguro con timeout)
    if ! cutycapt --insecure --url="$PROTO://$IP" --out="$OUTPUT_DIR/$IP.png" --max-wait=5000; then
        echo "⚠️ Falló la captura en: $IP"
        rm -f "$OUTPUT_DIR/$IP.png"
        continue
    fi

    # Verificar si la captura fue exitosa
    if [ -f "$OUTPUT_DIR/$IP.png" ]; then
        echo "📸 Captura guardada: $OUTPUT_DIR/$IP.png"
    else
        echo "⚠️ Falló la generación de la captura en: $IP"
    fi
done < <(prips "$RANGO_CIDR")

echo "✅ Proceso completado. Las capturas están en el directorio '$OUTPUT_DIR'."