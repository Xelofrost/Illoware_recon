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

# Crear directorio de salida
mkdir -p "$OUTPUT_DIR"

# Escanear puertos 80 y 443 con masscan
echo "🔍 Escaneando $RANGO_CIDR con masscan..."
masscan_temp=$(mktemp)
sudo masscan "$RANGO_CIDR" -p80,443 --open-only -oG "$masscan_temp" || {
    echo "❌ Fallo al ejecutar masscan. ¿Tienes permisos suficientes?";
    rm -f "$masscan_temp";
    exit 1;
}

# Procesar IPs y puertos
declare -A IP_PORTS
while IFS= read -r line; do
    if [[ $line =~ Host:\ ([0-9.]+).*Ports:\ ([0-9]+)/ ]]; then
        ip="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        IP_PORTS["$ip"]="${IP_PORTS["$ip"]} $port"
    fi
done < <(grep 'Host:' "$masscan_temp")
rm -f "$masscan_temp"

# Procesar cada IP
for ip in "${!IP_PORTS[@]}"; do
    ports="${IP_PORTS[$ip]}"
    
    # Determinar protocolo (HTTP si 80 está abierto, sino HTTPS)
    if [[ $ports =~ 80 ]]; then
        PROTO="http"
    else
        PROTO="https"
    fi

    echo "🔍 Comprobando $PROTO://$ip"

    # Capturar con cutycapt (timeout de 20 segundos)
    echo "📸 Intentando captura en $PROTO://$ip..."
    if timeout 20s cutycapt --insecure --url="$PROTO://$ip" --out="$OUTPUT_DIR/$ip.png" --max-wait=20000 2>/dev/null; then
        if [ -f "$OUTPUT_DIR/$ip.png" ]; then
            echo "✅ Captura exitosa: $OUTPUT_DIR/$ip.png"
        else
            echo "⚠️ La captura falló en: $ip"
        fi
    else
        echo "⌛ Tiempo excedido en $ip. Omitiendo..."
        rm -f "$OUTPUT_DIR/$ip.png"
    fi
done

echo "✅ Proceso completado. Las capturas están en '$OUTPUT_DIR'."