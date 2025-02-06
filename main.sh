#!/bin/bash
#bash ./reset.sh
figlet -f slant ILLOWARE
if [ -z "$1" ]; then
    echo "Error: No enviaste un dominio"
    echo "Uso: ./main.sh <dominio>"
    exit
fi

domain=$1
echo "Escaneando $domain"

#Estructura de carpetas

timestamp=$(date +"%Y-%m-%d_%H:%M:%S")
ruta_resultados=./resultados/$domain/$timestamp
mkdir -p "$ruta_resultados"
mkdir -p $ruta_resultados/raw
mkdir -p $ruta_resultados/clean
#Analisis infraestructura

dig +short A $domain > $ruta_resultados/clean/IP
dig +short MX $domain > $ruta_resultados/clean/MX
dig +short TXT $domain > $ruta_resultados/clean/TXT
dig +short NS $domain > $ruta_resultados/clean/NS
dig +short SRV $domain > $ruta_resultados/clean/SRV
dig +short AAAA $domain > $ruta_resultados/clean/AAAA
dig +short CNAME $domain > $ruta_resultados/clean/CNAME
dig +short SOA $domain > $ruta_resultados/clean/SOA
dig +short txt _dmarc.$domain > $ruta_resultados/clean/DMARC
dig +short txt default._domainkey $domain > $ruta_resultados/clean/DKIM

echo "Extrayendo rangos de IP"
while IFS= read -r ip; do
    whois -b "$ip" | grep 'inetnum' | awk '{print $2, $3, $4}' >> $ruta_resultados/clean/rangos_ripe
done < $ruta_resultados/clean/IP

echo "Realizando whois"
whois $domain > $ruta_resultados/raw/whois
echo "Realizando dig"
dig $domain > $ruta_resultados/raw/dig

curl -I https://$domain > $ruta_resultados/raw/headers
cat -s $ruta_resultados/raw/headers | grep -i Server | awk '{print $2}' >> $ruta_resultados/clean/header_server

echo "Realizando NMAP"

# Ejecutar Nmap y redirigir la salida a través de un while loop
sudo nmap -sS -Pn -sV -sC -O -vv --open --reason --min-hostgroup 16 --min-rate 100 --max-parallelism=10 -F -oA $ruta_resultados/raw/output_nmap $domain \
2>/dev/null | while IFS= read -r line; do
  # Mostrar el mensaje de inicio de escaneo
  if [[ "$line" == *"Starting Nmap"* ]]; then
    echo "Iniciando escaneo de Nmap..."
  fi

  # Mostrar los estados de los escaneos
  if [[ "$line" == *"Scanning"* ]]; then
    echo "Escaneando: $line"
  fi
done

echo "Escaneo de Nmap completado"

echo "Realizando GAU"
gau $domain --o $ruta_resultados/raw/gau

echo "Realizando Katana"
katana -silent -u $domain >> $ruta_resultados/raw/katana

echo "Realizando CTFR"
ctfr -d $domain 2>/dev/null | awk '/[-]/{print $2}' >> $ruta_resultados/raw/ctfr

#echo "Realizando AMASS"
#amass enum -d $domain >>$ruta_resultados/raw/amass

#cat $ruta_resultados/raw/katana $ruta_resultados/raw/ctfr | sort | uniq | httpx -silent | unfurl paths  >> $ruta_resultados/clean/PATHS
#cat $ruta_resultados/raw/gau | sort | uniq | httpx -silent >> $ruta_resultados/clean/Dominios_Subdominios

# Filtrar las URLs de GAU con httpx antes de continuar
echo "Filtrando las URLs de GAU con httpx..."

input_file_3="$ruta_resultados/raw/gau"
filtered_gau="$ruta_resultados/raw/gau_filtered"

# Filtrar las URLs de GAU para asegurarse de que respondan
cat "$input_file_3" | sort | uniq | httpx -silent > "$filtered_gau"

echo "Filtrado de GAU completado."

# Asignar las rutas a las variables
input_file_1="$ruta_resultados/raw/katana"
input_file_2="$ruta_resultados/raw/ctfr"
output_file="$ruta_resultados/clean/PATHS"  # Asigna la ruta de salida

# Verificar si output_file está correctamente asignado
if [ -z "$output_file" ]; then
  echo "Error: La variable output_file no tiene una ruta válida."
  exit 1
fi

# Contar el número total de URLs en los archivos raw
total_urls=$(cat "$input_file_1" "$input_file_2" "$filtered_gau" | sort | uniq | wc -l)

# Inicializar el contador
counter=0

echo "Total de URLs a procesar: $total_urls"

# Juntar los archivos raw katana, ctfr y el gau filtrado en el archivo de salida
cat "$input_file_1" "$input_file_2" "$filtered_gau" | sort | uniq | while IFS= read -r url; do
  # Verificar que la URL no esté vacía
  if [ -z "$url" ]; then
    continue
  fi

  # Si la URL contiene ".concat(", descartarla
  if [[ "$url" == *".concat("* ]]; then
    continue
  fi

  # Asegurarse de que la URL sea válida, si no, agregar el prefijo "https://"
  if [[ ! "$url" =~ ^https?:// ]]; then
    url="https://$url"
  fi

  # Obtener el código HTTP con curl, sin mostrar la salida
  http_code=$(curl -I -L --silent --write-out "%{http_code}" --output /dev/null "$url" 2>/dev/null)

  # Verificar que http_code es numérico antes de continuar
  if ! [[ "$http_code" =~ ^[0-9]+$ ]]; then
    continue
  fi

  # Si la URL responde con código HTTP 200, la agregamos al archivo con el código
  if [ "$http_code" -eq 200 ]; then
    echo "$url - HTTP Code: $http_code" >> "$output_file"
  fi

  # Incrementar el contador
  counter=$((counter + 1))

  # Mostrar el progreso cada 10 URLs
  if ((counter % 10 == 0)); then
    progress=$((counter * 100 / total_urls))
    echo "Progreso: $progress% completado ($counter de $total_urls URLs procesadas)"
  fi
done

# Contar las URLs procesadas en el archivo clean/PATHS
processed_urls=$(wc -l < "$output_file")

echo "Proceso completado. $processed_urls URLs procesadas."

# Revisar y eliminar archivos vacíos en la carpeta /clean
for file in "$ruta_resultados/clean"/*; do
  if [ ! -s "$file" ]; then
    echo "Eliminando archivo vacío: $file"
    rm "$file"
  fi
done

echo "# $domain" > /tmp/resultado.md
echo "## Infraestructura" >> /tmp/resultado.md

# Función para agregar contenido de archivos a una sección específica
function agregar_registros {
    tipo_registro=$1
    archivo_registro="$ruta_resultados/clean/$tipo_registro"
    
    # Solo agregar la sección si el archivo tiene contenido
    if [[ -s "$archivo_registro" ]]; then
        echo "### $tipo_registro" >> /tmp/resultado.md
        
        # Cambiar aquí para añadir tres # al inicio de cada línea
        sed 's/^/#### /' "$archivo_registro" >> /tmp/resultado.md
        
        echo "" >> /tmp/resultado.md  # AñadeNS una línea en blanco para separar secciones
    fi
}

# Agregar diferentes tipos de registros
agregar_registros "NS"
agregar_registros "IP"
agregar_registros "MX"
agregar_registros "TXT"
agregar_registros "CNAME"
agregar_registros "SRV"
agregar_registros "AAAA"
agregar_registros "SOA"
agregar_registros "DMARC"
agregar_registros "DKIM"
agregar_registros "rangos_ripe"
agregar_registros "header_server"

# Generar el mapa mental con markmap
echo "Generando Markmap..."
markmap /tmp/resultado.md --no-open

cp /tmp/resultado.html .