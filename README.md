# Iloware GitHub Tools

Este repositorio agrupa varios scripts Bash diseñados para facilitar tareas de reconocimiento de infraestructura y auditoría de dominios. Actualmente incluye los siguientes scripts:

1. **Recon Illoware** (`recon_illoware.sh`): Flujo completo de recolección de información (DNS, WHOIS, HTTP headers, escaneo Nmap, enumeración de rutas).
2. **Actualizar Resolvers** (`update_resolvers.sh`): Genera y mantiene actualizada una lista de resolvers DNS eficientes usando `dnsvalidator`.
3. **Recon Rango** (`recon_rango.sh`): Escanea un rango CIDR con `masscan`, captura capturas de pantalla de servicios HTTP/HTTPS.
4. **Reset** (`reset.sh`): Limpia resultados eliminando la carpeta `resultados/`.

---

## Índice

* [Requisitos](#requisitos)
* [Instalación](#instalaci%C3%B3n)
* [Scripts](#scripts)

  * [Recon Illoware](#recon-illoware)
  * [Actualizar Resolvers](#actualizar-resolvers)
  * [Recon Rango](#recon-rango)
  * [Reset](#reset)
* [Contribuciones](#contribuciones)
* [Licencia](#licencia)

---

## Requisitos

* Sistema operativo Linux (compatible con Debian/Ubuntu, CentOS, Kali Linux, macOS con Homebrew).
* Permisos `sudo` para instalación de dependencias y ejecución de escaneos.
* Herramientas de línea de comandos:

  * `bash`, `git`, `curl`, `whois`, `dig`, `nmap`, `masscan`, `cutycapt`.
  * Lenguajes/interpretes: `go`, `python3`, `pip3`, `npm`.
  * Gestores de paquetes: `apt-get`, `yum` o `brew`.

---

## Instalación

Clona el repositorio y dale permisos de ejecución a los scripts:

```bash
git clone https://github.com/tu-usuario/illoware-tools.git
cd illoware-tools
chmod +x *.sh
```

Opcionalmente, añade la carpeta de scripts al `PATH` en tu `~/.bashrc`:

```bash
export PATH="$PATH:$(pwd)"
```

---

## Scripts

### Recon Illoware

Flujo de reconocimiento completo para un dominio:

```bash
./recon_illoware.sh <dominio>
```

**Funcionalidades principales:**

* Comprobación y auto-instalación de dependencias.
* Recolección DNS (`dig`) para registros A, MX, TXT, NS, SRV, AAAA, CNAME, SOA, DMARC, DKIM.
* Extracción de rangos IP (`whois`).
* WHOIS y `dig` completos.
* Encabezados HTTP (`curl -I`).
* Escaneo de puertos y servicios con `nmap`.
* Enumeración de rutas con `gau`, `katana`, `ctfr`.
* Filtrado y verificación de URLs activas con `httpx`.
* Generación de directorios de resultados (`./resultados/<dominio>/<timestamp>`).
* Reporte en Markdown y HTML (via `markmap`).

### Actualizar Resolvers

Crea o actualiza el archivo `tools/resolvers.txt` con una lista de resolvers DNS:

```bash
./update_resolvers.sh
```

**Características:**

* Instala `dnsvalidator` si no está presente.
* Descarga y valida resolvers públicos.
* Filtra IP válidas y garantiza al menos 100 entradas.
* Añade resolvers de respaldo (Google, Cloudflare, Quad9).

### Recon Rango

Escanea un rango CIDR y captura screenshots de servicios web:

```bash
./recon_rango.sh <RANGO_CIDR>
# Ejemplo:
./recon_rango.sh 172.233.0.0/16
```

* Escanea puertos 80 y 443 con `masscan`.
* Procesa IPs abiertas y determina protocolo (http/https).
* Captura pantallas con `cutycapt` en `capturas/`.

### Reset

Elimina todos los resultados previos:

```bash
./reset.sh
```

---

## Contribuciones

1. Haz un fork del proyecto.
2. Crea un branch con tu feature o corrección (`git checkout -b feature/nombre`).
3. Realiza tus cambios y haz commit (`git commit -m "Agrega descripción"`).
4. Envía tus cambios al repositorio remoto (`git push origin feature/nombre`).
5. Abre un Pull Request describiendo tus modificaciones.

---

## Licencia

Este proyecto está licenciado bajo la [MIT License](LICENSE).