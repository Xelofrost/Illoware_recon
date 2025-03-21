#!/bin/bash
set -euo pipefail

TOOLS_DIR="$(pwd)/tools"
RESOLVERS_FILE="$TOOLS_DIR/resolvers.txt"

# Función para mostrar mensaje de finalización
show_completion() {
    echo -e "\n[✅] Proceso completado exitosamente a las $(date +'%T')"
    echo "--------------------------------------------------"
}

# Función para instalar dnsvalidator (compatible con Kali Linux)
install_dnsvalidator() {
    echo "[🔧] Instalando dnsvalidator..."
    
    # Instalar dependencias necesarias
    echo "[📦] Instalando python3-venv..."
    sudo apt-get install -y python3-venv > /dev/null 2>&1
    
    # Clonar repositorio
    echo "[📥] Clonando dnsvalidator..."
    git clone https://github.com/vortexau/dnsvalidator.git "$TOOLS_DIR/dnsvalidator" > /dev/null 2>&1
    
    # Crear y activar entorno virtual
    echo "[🐍] Creando entorno virtual..."
    cd "$TOOLS_DIR/dnsvalidator"
    python3 -m venv .venv
    source .venv/bin/activate
    
    # Instalar dentro del entorno virtual
    echo "[⚙️] Instalando dependencias..."
    pip install . > /dev/null 2>&1
    
    # Crear enlace simbólico global
    echo "[🔗] Creando enlace simbólico..."
    sudo ln -sf "$TOOLS_DIR/dnsvalidator/.venv/bin/dnsvalidator" /usr/local/bin/
    
    # Desactivar entorno
    deactivate
    cd - >/dev/null
    
    echo "[⚡] dnsvalidator instalado en entorno virtual"
}

# Función principal de actualización
update_resolvers() {
    echo -e "\n[🌐] Iniciando actualización de resolvers DNS"
    echo "--------------------------------------------------"
    mkdir -p "$TOOLS_DIR"

    # Verificar dnsvalidator
    if ! command -v dnsvalidator >/dev/null 2>&1; then
        install_dnsvalidator
    else
        echo "[🔍] dnsvalidator ya está instalado"
    fi

    # Generar lista
    echo "[🔄] Generando nueva lista de resolvers..."
    dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 50 -o "$RESOLVERS_FILE.tmp"

    # Añadir resolvers de respaldo
    echo "[📦] Añadiendo resolvers de confianza..."
    {
        echo -e "\n# Resolvers de respaldo"
        echo -e "8.8.8.8\t# Google DNS"
        echo -e "1.1.1.1\t# Cloudflare DNS" 
        echo -e "9.9.9.9\t# Quad9 DNS"
    } >> "$RESOLVERS_FILE.tmp"

    # Filtrar y validar
    echo "[🧹] Filtrando IPs válidas..."
    awk 'NF && $0!~/[^0-9.]/' "$RESOLVERS_FILE.tmp" | sort -u > "$RESOLVERS_FILE.tmp2"

    # Verificación final
    if [[ $(wc -l < "$RESOLVERS_FILE.tmp2") -ge 100 ]]; then
        mv "$RESOLVERS_FILE.tmp2" "$RESOLVERS_FILE"
        echo -e "\n[📊] Estadísticas finales:"
        echo "---------------------------------"
        echo "• Total resolvers: $(wc -l < "$RESOLVERS_FILE")"
        echo "• Top 5 más rápidos:"
        head -n 5 "$RESOLVERS_FILE" | awk '{print "  → "$0}'
        show_completion
    else
        echo -e "\n[❌] Error crítico: Lista insuficiente"
        echo "• Se requieren mínimo 100 resolvers"
        echo "• Se encontraron: $(wc -l < "$RESOLVERS_FILE.tmp2")"
        exit 1
    fi

    # Limpieza
    rm -f "$RESOLVERS_FILE".tmp*
}

# Ejecución principal corregida
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo -e "\n🛠️  Script de actualización de resolvers DNS"
    echo "=================================================="
    update_resolvers
    echo -e "\n[ℹ️]  Usa esta lista en tu script principal con:"
    echo "     $RESOLVERS_FILE"
fi