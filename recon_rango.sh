#!/bin/bash

# Verificar si se proporcionan los parámetros correctos
if [ "$#" -ne 2 ]; then
    echo "Uso: $0 <IP_INICIAL> <IP_FINAL>"
    echo "Ejemplo: $0 192.168.1.1 192.168.1.254"
    exit 1
fi

IP_INICIAL=$1
IP_FINAL=$2
OUTPUT_DIR="capturas"

# Crear directorio de salida si no existe
mkdir -p "$OUTPUT_DIR"

# Generar lista de IPs y procesarlas
prips "$IP_INICIAL" "$IP_FINAL" | while read -r IP; do
    echo "Escaneando: http://$IP"
    
    # Intentar capturar la página con cutycapt
    cutycapt --url="http://$IP" --out="$OUTPUT_DIR/$IP.png" --max-wait=5000
    
    # Verificar si la captura fue exitosa
    if [ -f "$OUTPUT_DIR/$IP.png" ]; then
        echo "✅ Captura guardada: $OUTPUT_DIR/$IP.png"
    else
        echo "❌ Falló la captura en: $IP"
    fi
done

echo "Proceso completado. Las capturas están en el directorio '$OUTPUT_DIR'."
