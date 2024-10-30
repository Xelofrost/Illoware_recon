from selenium.webdriver.common.by import By 
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC 
from selenium.webdriver.chrome.options import Options 
from selenium import webdriver 
import argparse 
import re

# Función para limpiar el dominio y extraer solo el nombre
def limpiar_dominio(url):
    # Elimina el prefijo "http://" o "https://" si está presente
    url = re.sub(r'^https?://', '', url)
    # Extrae solo el nombre del dominio (antes del primer punto)
    dominio = url.split('/')[0].split('.')[0]
    return dominio

# Configuración de argparse para recibir el dominio como argumento
parser = argparse.ArgumentParser(description="Script para buscar un dominio en HackerTarget.")
parser.add_argument("dominio", type=str, help="Dominio a buscar en HackerTarget")
args = parser.parse_args()

# Limpiar el dominio ingresado por el usuario
dominio_limpio = limpiar_dominio(args.dominio)

# Configuración del navegador
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

driver = webdriver.Chrome(options=chrome_options)

# Navegar al sitio web
driver.get("https://hackertarget.com/as-ip-lookup/")

# Buscar el campo de entrada y enviar solo el nombre del dominio
search = driver.find_element(By.NAME, "theinput")
search.send_keys(dominio_limpio)
search.submit()

# Esperar el resultado y mostrarlo
try:
    element = WebDriverWait(driver, 20).until(
        EC.visibility_of_element_located((By.ID, "myTable_wrapper"))
    )
    print(element.text)
finally:
    driver.quit()