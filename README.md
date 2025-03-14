# XELOWARE - Herramienta Integral de Análisis y Recon de Dominios

Este repositorio contiene un conjunto de herramientas para realizar análisis de seguridad y recopilación de información de dominios. Incluye:

- Un **script principal en Bash** (`Illoware.sh`) que automatiza diversas fases del análisis (DNS, WHOIS, escaneo con Nmap, enumeración de URLs, generación de reportes, etc.).
- Un **archivo `package.json`** para gestionar dependencias de Node.js.
- Un **archivo `requirements.txt`** para gestionar dependencias de Python.
- Un **script de reseteo** (`reset.sh`) que limpia los resultados generados.

> **Disclaimer:**  
> Los archivos `package.json` y `requirements.txt` se incluyen como soporte para agilizar la gestión y actualización de dependencias en entornos donde se requiera una intervención manual. Sin embargo, no son indispensables para el funcionamiento del script principal, ya que éste descarga e instala automáticamente todas las dependencias necesarias durante su ejecución.

---

## Contenido del Repositorio

- **Xeloware.sh**:  
  Script principal en Bash que realiza el análisis de seguridad de un dominio. Entre sus funciones se incluyen:  
  - Verificar e instalar dependencias necesarias (gcc, go, python3, pip3, git, npm, bc, figlet, etc.).
  - Realizar consultas DNS, WHOIS, encabezados HTTP, escaneo con Nmap y enumeración de URLs.
  - Organizar los resultados en una estructura de directorios y generar reportes (incluyendo un HTML generado con markmap, si está disponible).

- **package.json**:  
  Archivo de configuración para dependencias de Node.js.  
  - Permite actualizar las dependencias utilizando herramientas como `npm-check-updates`.

- **requirements.txt**:  
  Archivo que lista las dependencias de Python necesarias para complementar el funcionamiento del proyecto.  
  - Se puede actualizar ejecutando `pip freeze > requirements.txt` después de actualizar los paquetes.

- **reset.sh**:  
  Script en Bash para limpiar la carpeta de resultados.

---

## Cómo Usar los Scripts

### 1. Script Principal `Illoware.sh`

**Requisitos Previos:**
- Sistema operativo basado en Linux (recomendado Ubuntu/Debian)
- Acceso a internet para descargar dependencias
- Permisos de ejecución (se configuran automáticamente)

**Pasos:**

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/Xelofrost/Illoware.git
   cd Illoware
   ```

2. **Da permisos de ejecución:**
   ```bash
   chmod +x Illoware.sh reset.sh
   ```

3. **Ejecuta el script con un dominio:**
   (Reemplaza `example.com` por tu dominio objetivo)
   ```bash
   ./Illoware.sh example.com
   ```

**Qué ocurre durante la ejecución:**

- Verifica e instala automáticamente dependencias faltantes (ej: nmap, subfinder, httpx).
- Crea una estructura de directorios `results/example.com/`.
- Ejecuta todas las fases de análisis y guarda resultados en:
  - `results/example.com/dns/`
  - `results/example.com/nmap/`
  - `results/example.com/urls/`
  - `results/example.com/reports/`
- Al finalizar, muestra una ruta al reporte principal:
  ```bash
  [+] Reporte HTML generado en: results/example.com/reports/overview.html
  ```

### 2. Script de Reseteo `reset.sh`

Para eliminar todos los resultados generados:
```bash
./reset.sh
```

El script borrará la carpeta de resultados directamente (debe estar en el mismo directorio que Illoware.sh).

**Notas Importantes**

- **Primera Ejecución:** La primera vez puede tomar varios minutos mientras descarga e instala herramientas externas.
- **Permisos de Instalación:** Es recomendable ejecutarlo con sudo la primera vez para que todas las dependencias se descarguen sin problemas.
- **Resultados:** Todos los archivos de salida se organizan jerárquicamente en la carpeta `results/` para facilitar el análisis posterior.