#!/bin/bash

#Leer cada línea del archivo domains
while IFS= read domain; do
    #Ejecutar el script asn.py.
    python3 scrapping-asn.py --input "$domain" --output "output/"
done < domains_definitive