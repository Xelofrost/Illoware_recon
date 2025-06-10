#!/bin/bash
set -euo pipefail

# Función para manejar errores (simula catch)
error_handler() {
    local exit_code=$?
    local line_no=$1
    echo -e "\n[❌] Error en la línea $line_no. Código de salida: $exit_code" >&2
    echo "[!] Se ha detenido la ejecución del script."
    exit $exit_code
}
# Establecer la trampa para capturar errores y pasar la línea donde ocurrió.
trap 'error_handler ${LINENO}' ERR

# Añadir directorio de herramientas al PATH desde el inicio
TOOLS_DIR="$(pwd)/tools"
export PATH="$PATH:$TOOLS_DIR/go/bin"
RESOLVERS_FILE="$TOOLS_DIR/resolvers.txt"  # <-- Nueva línea añadida

# Función de log silencioso: muestra mensajes solo si QUIET no está definido.
log() {
    if [ -z "${QUIET-}" ]; then
        echo "$@"
    fi
}

# Función para determinar si todas las dependencias están instaladas
are_all_dependencies_installed() {
    local commands=("gcc" "go" "python3" "pip3" "git" "npm" "bc" "figlet" "dig" "whois" "curl" "nmap" "gau" "katana" "ctfr" "httpx" "markmap")
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            return 1
        fi
    done
    # Verifica que python3 tenga ensurepip (para entornos virtuales)
    if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# Corrige el hostname en /etc/hosts si no se encuentra la entrada actual
fix_hostname() {
    local current_hostname
    current_hostname=$(hostname)
    if ! grep -q "$current_hostname" /etc/hosts; then
        if [ -z "${QUIET-}" ]; then
            echo "127.0.0.1 $current_hostname" | sudo tee -a /etc/hosts
        else
            echo "127.0.0.1 $current_hostname" | sudo tee -a /etc/hosts >/dev/null
        fi
    fi
}

# Función para instalar dependencias usando gestores de paquetes
install_with_pkg_manager() {
    local dep_name="$1"
    local pkg_name="$2"
    if [ -z "${QUIET-}" ]; then
        echo "El comando '$dep_name' no se encontró. Instalando paquete '$pkg_name'..."
    fi
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y "$pkg_name"
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y "$pkg_name"
    elif command -v brew >/dev/null 2>&1; then
        brew install "$pkg_name"
    else
        echo "No se pudo determinar un gestor de paquetes para instalar '$dep_name'. Instálalo manualmente."
        exit 1
    fi
}

# Función para instalar Go (dentro de la carpeta tools)
install_go() {
    if ! command -v go >/dev/null 2>&1; then
        if [ -z "${QUIET-}" ]; then
            echo "[+] Go no encontrado. Instalando Go globalmente usando el gestor de paquetes..."
        fi
        install_with_pkg_manager "go" "golang"
        if [ -z "${QUIET-}" ]; then
            echo "[+] Go instalado globalmente."
        fi
    fi
    # Establece GOPATH e incluye el directorio de binarios de Go (global)
    export GOPATH="$(go env GOPATH)"
    export PATH="$PATH:$(go env GOPATH)/bin"
}


# Función para mostrar el banner de marca con Figlet.
show_banner() {
    if ! command -v figlet >/dev/null 2>&1; then
        install_with_pkg_manager "figlet" "figlet"
    fi
    figlet -f slant ILLOWARE
}

# Valida que el usuario pase un dominio y que tenga un formato razonable
validate_input() {
    if [ $# -ne 1 ]; then
        echo "Uso: $0 <dominio>" >&2
        exit 1
    fi
    local domain_regex='^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$'
    if ! [[ $1 =~ $domain_regex ]]; then
        echo "Dominio inválido: '$1'" >&2
        exit 1
    fi
}


# Función para verificar e instalar dependencias (la salida se controla mediante la función log)
check_dependencies() {
    # Función auxiliar para instalar herramientas Go en su propio subdirectorio
    install_go_tool() {
        local tool_name="$1"
        shift
        if [ -z "${QUIET-}" ]; then
            echo "[+] Instalando $tool_name globalmente..."
        fi
        go install "$@"
        if [ -z "${QUIET-}" ]; then
            echo "[+] $tool_name instalado globalmente en $(go env GOPATH)/bin."
        fi
    }   

    # gcc
    if ! command -v gcc >/dev/null 2>&1; then
        install_with_pkg_manager "gcc" "build-essential"
    fi

    # Habilitar CGO
    export CGO_ENABLED=1

    # Go
    if ! command -v go >/dev/null 2>&1; then
        install_go
    fi

    # python3
    if ! command -v python3 >/dev/null 2>&1; then
        install_with_pkg_manager "python3" "python3"
    fi

    # pip3
    if ! command -v pip3 >/dev/null 2>&1; then
        install_with_pkg_manager "pip3" "python3-pip"
    fi

    # ensurepip (para entornos virtuales)
    if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 -V | awk '{print $2}')
        if [[ $PYTHON_VERSION == 3.13* ]]; then
            install_with_pkg_manager "python3-venv" "python3.13-venv"
        else
            install_with_pkg_manager "python3-venv" "python3-venv"
        fi
    fi

    # git
    if ! command -v git >/dev/null 2>&1; then
        install_with_pkg_manager "git" "git"
    fi

    # npm
    if ! command -v npm >/dev/null 2>&1; then
        install_with_pkg_manager "npm" "npm"
    fi

    # bc
    if ! command -v bc >/dev/null 2>&1; then
        install_with_pkg_manager "bc" "bc"
    fi

    # Dependencias específicas
    local dependencies=(figlet dig whois curl nmap gau katana ctfr httpx markmap sed awk)
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            case "$cmd" in
                figlet)
                    install_with_pkg_manager "figlet" "figlet"
                    ;;
                dig)
                    install_with_pkg_manager "dig" "dnsutils"
                    ;;
                whois)
                    install_with_pkg_manager "whois" "whois"
                    ;;
                curl)
                    install_with_pkg_manager "curl" "curl"
                    ;;
                nmap)
                    install_with_pkg_manager "nmap" "nmap"
                    ;;
                gau)
                    if command -v go >/dev/null 2>&1; then
                        install_go_tool gau github.com/lc/gau/v2/cmd/gau@latest
                    else
                        echo "Falta Go para instalar gau."
                        exit 1
                    fi
                    ;;
                katana)
                    if command -v go >/dev/null 2>&1; then
                        install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
                    else
                        echo "Falta Go para instalar katana."
                        exit 1
                    fi
                    ;;
                ctfr)
                    if command -v pip3 >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
                        local ctfr_dir="/usr/local/ctfr"
                        if [ ! -d "$ctfr_dir" ]; then
                            sudo git clone https://github.com/UnaPibaGeek/ctfr.git "$ctfr_dir"
                        fi
                        cd "$ctfr_dir"
                        if [ ! -d "venv" ] || [ ! -f "venv/bin/activate" ]; then
                            sudo rm -rf venv
                            python3 -m venv venv
                        fi
                        source venv/bin/activate
                        pip install --upgrade pip
                        pip install -r requirements.txt
                        deactivate
                        {
                            echo "#!/bin/bash"
                            echo "source \"$ctfr_dir/venv/bin/activate\""
                            echo "python \"$ctfr_dir/ctfr.py\" \"\$@\""
                        } | sudo tee /usr/local/bin/ctfr >/dev/null
                        sudo chmod +x /usr/local/bin/ctfr
                        cd - >/dev/null
                    else
                        echo "Falta pip3 o git para instalar ctfr."
                        exit 1
                    fi
                    ;;
                httpx)
                    if command -v go >/dev/null 2>&1; then
                        install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
                        sudo rm -fr /usr/bin/httpx
                        sudo ln -s "$(go env GOPATH)/bin/httpx" /usr/bin/httpx
                    else
                        echo "Falta Go para instalar httpx."
                        exit 1
                    fi
                    ;;
                markmap)
                    if command -v npm >/dev/null 2>&1; then
                        npm install -g markmap-cli
                    else
                        echo "Falta npm para instalar markmap-cli."
                        exit 1
                    fi
                    ;;
                sed|awk)
                    ;;
                *)
                    echo "No se reconoce el método de instalación para '$cmd'. Instálalo manualmente."
                    exit 1
                    ;;
            esac
        fi
    done
}


# Crea la estructura de directorios para almacenar los resultados.
create_directories() {
    local domain="$1"
    timestamp=$(date +"%Y-%m-%d_%H%M%S")
    base_dir="./resultados/$domain/$timestamp"
    mkdir -p "$base_dir/raw" "$base_dir/clean"
    echo "$base_dir"
}

# Recopila la información DNS básica mediante dig y guarda los resultados.
collect_dns() {
    local domain="$1"
    local base_dir="$2"
    local clean_dir="$base_dir/clean"
    
    # Función auxiliar para ejecutar dig con reintentos
    dig_with_retry() {
        local query_type="$1"
        local target="$2"
        local output_file="$3"
        
        # Desactiva temporalmente el exit-on-error en esta función
        set +e

        # Construir una lista de resolvers: se mezclan algunos aleatorios del archivo, resolvers fijos y los primeros 10 del archivo
        local resolvers=()
        if [ -f "$RESOLVERS_FILE" ]; then
            # Se agregan resolvers aleatorios (si el archivo existe)
            resolvers+=( $(shuf -n 5 "$RESOLVERS_FILE" 2>/dev/null) )
            # Y los primeros 10
            resolvers+=( $(awk 'NR<=10' "$RESOLVERS_FILE" 2>/dev/null) )
        fi
        # Añadimos algunos resolvers públicos fijos
        resolvers+=( "8.8.8.8" "1.1.1.1" "9.9.9.9" )
        
        # Eliminar duplicados
        mapfile -t unique_resolvers < <(printf "%s\n" "${resolvers[@]}" | awk '!seen[$0]++')
        
        for resolver in "${unique_resolvers[@]}"; do
            log "  Probando resolver: $resolver"
            # Se usa timeout para evitar bloqueos; si falla, se continúa al siguiente resolver
            if timeout 2 dig +short +time=2 +tries=1 @"$resolver" version.bind CHAOS TXT >/dev/null 2>&1; then
                log "  Resolver activo: $resolver"
                # Ejecuta la consulta y redirige posibles errores sin interrumpir el script
                dig +short +time=3 +tries=2 @"$resolver" "$query_type" "$target" > "$output_file" 2>/dev/null || true
                set -e  # Restablece el modo fail fast
                return 0
            else
                log "  Resolver $resolver no respondió, continuando..."
            fi
        done
        
        log "  Usando resolver del sistema"
        dig +short "$query_type" "$target" > "$output_file" 2>/dev/null || true
        
        set -e  # Restablece el modo fail fast al finalizar la función
    }


    # Ejecutar consultas para cada tipo de registro
    dig_with_retry A "$domain" "$clean_dir/IP"
    dig_with_retry MX "$domain" "$clean_dir/MX"
    dig_with_retry TXT "$domain" "$clean_dir/TXT"
    dig_with_retry NS "$domain" "$clean_dir/NS"
    dig_with_retry SRV "$domain" "$clean_dir/SRV"
    dig_with_retry AAAA "$domain" "$clean_dir/AAAA"
    dig_with_retry CNAME "$domain" "$clean_dir/CNAME"
    dig_with_retry SOA "$domain" "$clean_dir/SOA"
    dig_with_retry TXT "_dmarc.$domain" "$clean_dir/DMARC"
    dig_with_retry TXT "default._domainkey.$domain" "$clean_dir/DKIM"
}

# Extrae los rangos de IP utilizando whois sobre cada IP del registro A.
extract_ip_ranges() {
    local base_dir="$1"
    local clean_dir="$base_dir/clean"
    while IFS= read -r ip; do
        whois -b "$ip" | grep 'inetnum' | awk '{print $2, $3, $4}' >> "$clean_dir/rangos_ripe"
    done < "$clean_dir/IP"
}

# Ejecuta whois y una consulta completa con dig para el dominio.
run_whois_and_dig() {
    local domain="$1"
    local base_dir="$2"
    local raw_dir="$base_dir/raw"
    whois "$domain" > "$raw_dir/whois"
    dig "$domain" > "$raw_dir/dig"
}

# Obtiene los encabezados HTTP y extrae el valor del servidor.
get_http_headers() {
    local domain="$1"
    local base_dir="$2"
    local raw_dir="$base_dir/raw"
    local clean_dir="$base_dir/clean"
    curl -s -I "https://$domain" > "$raw_dir/headers"
    cat -s "$raw_dir/headers" | grep -i Server | awk '{print $2}' >> "$clean_dir/header_server"
}

# Escaneo Nmap simplificado
run_nmap() {
    local domain="$1"
    local base_dir="$2"
    local raw_dir="$base_dir/raw"
    
    log "  [+] Iniciando escaneo Nmap..."
    sudo nmap -sS -Pn -sV -sC -O -vv --open --reason -F -oA "$raw_dir/output_nmap" "$domain" >/dev/null 2>&1
}

# Ejecuta herramientas de enumeración
run_enumeration_tools() {
    local domain="$1"
    local base_dir="$2"
    local raw_dir="$base_dir/raw"
    
    log "  [+] Ejecutando GAU..."
    gau "$domain" --o "$raw_dir/gau" 2>/dev/null || true

    log "  [+] Ejecutando Katana..."
    katana scan -u "https://$domain" > "$raw_dir/katana" 2>/dev/null || true

    log "  [+] Ejecutando CTFR..."
    ctfr -d "$domain" 2>/dev/null | awk '/[-]/{print $2}' > "$raw_dir/ctfr" || true

    log "  [+] Combinando resultados de enumeración..."
    # Se asegura que existan los archivos requeridos para el posterior procesamiento.
    touch "$raw_dir"/{katana,ctfr,gau}
}


# Procesamiento de URLs con xargs y paralelismo controlado
process_urls() {
    local base_dir="$1"
    local raw_dir="$base_dir/raw"
    local clean_dir="$base_dir/clean"
    
    echo "  [+] Procesando URLs..."
    # Combina directamente las salidas de Katana, CTFR y GAU sin filtrado previo.
    # Se normalizan las URLs agregando "http://" en aquellas que no lo tengan.
    cat "$raw_dir/katana" "$raw_dir/ctfr" "$raw_dir/gau" 2>/dev/null \
        | sed -E '/^https?:\/\//! s#^#http://#' \
        | sort -u > "$raw_dir/all_urls"
    
    local total
    total=$(wc -l < "$raw_dir/all_urls")
    echo "  [+] Verificando URLs activas..."
    > "$clean_dir/PATHS"  # Archivo final en clean
    
    # Construye el comando de httpx, añadiendo los resolvers si el archivo existe
    local httpx_cmd=("httpx" "-threads" "200" "-mc" "200,403,500" "-timeout" "5" "--no-color" "-silent" "--status-code")
    if [ -f "$RESOLVERS_FILE" ]; then
        resolvers=$(paste -sd, "$RESOLVERS_FILE")
        httpx_cmd+=("-r" "$resolvers")
    fi
    
    (cat "$raw_dir/all_urls" | "${httpx_cmd[@]}" | awk '{print $1}' >> "$clean_dir/PATHS") &
    local httpx_pid=$!
    
    local counter=0
    while kill -0 "$httpx_pid" 2>/dev/null; do
        counter=$(wc -l < "$clean_dir/PATHS")
        percent=$(echo "scale=1; $counter*100/$total" | bc -l)
        printf "    Progreso: %d/%d (%s%%)\r" "$counter" "$total" "$percent"
        sleep 1
    done
    
    counter=$(wc -l < "$clean_dir/PATHS")
    percent=$(echo "scale=1; $counter*100/$total" | bc -l)
    printf "    Progreso: %d/%d (%s%%)\n" "$counter" "$total" "$percent"
    
    echo "    URLs totales: $total | URLs activas: $counter"
}

# Elimina archivos vacíos
clean_empty_files() {
    local base_dir="$1"
    local clean_dir="$base_dir/clean"
    
    log "  [+] Limpiando archivos vacíos..."
    find "$clean_dir" -type f -empty -delete
}

# Función para crear README.txt con descripciones de archivos
create_readme() {
    local base_dir="$1"
    local clean_dir="$base_dir/clean"
    local readme_file="$clean_dir/README.txt"
    
    log "  [+] Generando README.txt con descripciones de archivos..."
    
    echo "Este directorio contiene los resultados del análisis de seguridad del dominio." > "$readme_file"
    echo "" >> "$readme_file"
    echo "Archivos en este directorio:" >> "$readme_file"
    
    local file_descriptions=(
        "IP: Lista de direcciones IPv4 asociadas al dominio."
        "MX: Registros de intercambio de correo."
        "TXT: Registros de texto con políticas SPF, DKIM, DMARC."
        "NS: Servidores de nombres DNS."
        "SRV: Registros de servicios."
        "AAAA: Direcciones IPv6 asociadas."
        "CNAME: Alias de nombres canónicos."
        "SOA: Información de la zona DNS."
        "DMARC: Política de autenticación de correo."
        "DKIM: Firma de correo electrónico."
        "rangos_ripe: Rangos de direcciones IP."
        "header_server: Servidor web detectado."
        "PATHS: URLs activas detectadas."
    )
    
    for entry in "${file_descriptions[@]}"; do
        IFS=':' read -r filename description <<< "$entry"
        filename=$(echo "$filename" | xargs)
        if [[ -f "$clean_dir/$filename" ]]; then
            echo "- $filename: ${description# }" >> "$readme_file"
        fi
    done
    
    echo "" >> "$readme_file"
}

# Genera reporte final
generate_report() {
    local domain="$1"
    local base_dir="$2"
    
    log "  [+] Generando reporte..."
    
    local markdown_file="/tmp/resultado.md"
    echo "# Reporte de análisis para $domain" > "$markdown_file"
    echo "" >> "$markdown_file"
    echo "## Información general" >> "$markdown_file"
    echo "- Dominio: $domain" >> "$markdown_file"
    echo "- Fecha: $(date)" >> "$markdown_file"
    echo "" >> "$markdown_file"
    
    # Sección DNS con verificaciones de existencia de archivos
    if [[ -f "$base_dir/clean/IP" ]]; then
        echo "## DNS" >> "$markdown_file"
        echo "- **IPs**: $(cat "$base_dir/clean/IP" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/MX" ]]; then
        echo "- **MX**: $(cat "$base_dir/clean/MX" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/TXT" ]]; then
        echo "- **TXT**: $(cat "$base_dir/clean/TXT" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/NS" ]]; then
        echo "- **NS**: $(cat "$base_dir/clean/NS" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/SRV" ]]; then
        echo "- **SRV**: $(cat "$base_dir/clean/SRV" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/AAAA" ]]; then
        echo "- **AAAA**: $(cat "$base_dir/clean/AAAA" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/CNAME" ]]; then
        echo "- **CNAME**: $(cat "$base_dir/clean/CNAME" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/SOA" ]]; then
        echo "- **SOA**: $(cat "$base_dir/clean/SOA" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/DMARC" ]]; then
        echo "- **DMARC**: $(cat "$base_dir/clean/DMARC" | tr '\n' ' ')" >> "$markdown_file"
    fi
    
    if [[ -f "$base_dir/clean/DKIM" ]]; then
        echo "- **DKIM**: $(cat "$base_dir/clean/DKIM" | tr '\n' ' ')" >> "$markdown_file"
    fi
    echo "" >> "$markdown_file"
    
    # Sección de URLs activas
    if [[ -f "$base_dir/clean/PATHS" ]]; then
        echo "## URLs activas" >> "$markdown_file"
        while read -r url; do
            echo "- $url" >> "$markdown_file"
        done < "$base_dir/clean/PATHS"
        echo "" >> "$markdown_file"
    fi
    
    # Generación del HTML con markmap
    if command -v markmap >/dev/null 2>&1; then
        markmap "$markdown_file" --no-open
        cp /tmp/resultado.html "$base_dir/"
        log "  [+] Reporte HTML generado: $base_dir/resultado.html"
    else
        log "  [-] markmap no está instalado. No se generará el reporte HTML."
    fi
}

# Función principal
main() {
    # 1. Verificar e instalar dependencias primero
    check_dependencies
    fix_hostname
    
    # 2. Mostrar banner solo después de asegurar que figlet está instalado
    show_banner
    
    # 3. Validar entrada de usuario
    validate_input "$1"
    local domain="$1"
    log "[+] Dominio validado: $domain"
    
    # 4. Verificar resolvers
    if [ ! -f "$RESOLVERS_FILE" ]; then
        log "[!] Advertencia: No se encontró archivo de resolvers en $RESOLVERS_FILE"
        log "    Ejecuta './update_resolvers.sh' para obtener la lista actualizada"
    fi
    
    # 5. Crear estructura de directorios
    local base_dir
    base_dir=$(create_directories "$domain")
    log "[+] Directorios creados: $base_dir"
    
    # 6. Fases de ejecución
    log "[+] Fase de recolección DNS"
    collect_dns "$domain" "$base_dir"
    
    log "[+] Fase de rangos IP"
    extract_ip_ranges "$base_dir"
    
    log "[+] Fase WHOIS/DIG"
    run_whois_and_dig "$domain" "$base_dir"
    
    log "[+] Fase headers HTTP"
    get_http_headers "$domain" "$base_dir"
    
    log "[+] Fase escaneo Nmap"
    run_nmap "$domain" "$base_dir"
    
    log "[+] Fase enumeración"
    run_enumeration_tools "$domain" "$base_dir"
    
    log "[+] Fase procesamiento URLs"
    process_urls "$base_dir"
    
    log "[+] Limpieza final"
    clean_empty_files "$base_dir"
    
    log "[+] Generando documentación"
    create_readme "$base_dir"
    
    log "[+] Generando reporte final"
    generate_report "$domain" "$base_dir"
    
    # 7. Resultados finales
    log "[+] Script completado exitosamente!"
    log "    Resultados en: $base_dir"
    if [[ -f "$base_dir/resultado.html" ]]; then
        log "    Reporte HTML: $base_dir/resultado.html"
    fi
}

main "$@"