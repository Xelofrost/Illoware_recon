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
sudo nmap -sS -Pn -sV -sC -O -vv --open --reason --min-hostgroup 16 --min-rate 100 --max-parallelism=10 -F -oA $ruta_resultados/raw/output_nmap $domain

echo "Realizando Katana"
katana -silent -u $domain >> $ruta_resultados/raw/katana

echo "Realizando CTFR"
ctfr -d $domain >> $ruta_resultados/raw/ctfr

echo "Realizando GAU"
gau $domain >> $ruta_resultados/raw/gau

#echo "Realizando AMASS"
#amass enum -d $domain >>$ruta_resultados/raw/amass

cat $ruta_resultados/raw/katana $ruta_resultados/raw/ctfr | sort | uniq | httpx -silent | unfurl paths  >> $ruta_resultados/clean/PATHS
cat $ruta_resultados/raw/gau | sort | uniq | httpx -silent >> $ruta_resultados/clean/Dominios_Subdominios

#echo "Tomando capturas de pantalla... TODO"
#gowitness scan file -f $ruta_resultados/clean/Dominios_Subdominios --write-csv

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