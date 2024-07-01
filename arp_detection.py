#Aldo Alcántara Martínez  Boleta:2019630578  Grupo:6CV2
#Materia:GOBIERNO DE TI|COMPUTER SECURITY

from scapy.all import ARP, Ether, srp  # Importamos funciones de Scapy para gestionar paquetes ARP y Ethernet
import os

def get_true_mac(ip):
    # Creamos un paquete ARP para la IP objetivo
    arp_request = ARP(pdst=ip)
    # Creamos un paquete Ethernet de broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combinamos los paquetes ARP y Ethernet
    arp_request_broadcast = broadcast / arp_request
    # Enviamos el paquete y recibimos las respuestas
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Verificamos si recibimos alguna respuesta
    if answered_list:
        # Devolvemos la dirección MAC de la primera respuesta recibida
        return answered_list[0][1].hwsrc
    else:
        # Generamos una excepción si no se recibe ninguna respuesta
        raise Exception(f"No se recibió respuesta ARP para la IP {ip}")

def get_arp_table_entry(ip):
    # Ejecutamos el comando 'arp -a' y obtenemos la salida
    arp_table = os.popen("arp -a").read()
    # Iteramos sobre cada línea de la tabla ARP
    for line in arp_table.split('\n'):
        # Verificamos si la línea contiene la IP del objetivo
        if ip in line:
            # Devolvemos la dirección MAC
            return line.split()[1]
    # Si no encontramos la IP en la tabla ARP, devolvemos None
    return None

def main():
    # Solicitamos la IP del router al usuario
    gateway_ip = input("Introduce la IP del router: ")

    try:
        # Obtenemos la dirección MAC real del router
        true_mac = get_true_mac(gateway_ip)
        print(f"Dirección MAC verdadera del router: {true_mac}")

        # Obtenemos la dirección MAC registrada en la tabla ARP
        arp_table_mac = get_arp_table_entry(gateway_ip)
        print(f"Dirección MAC en la tabla ARP: {arp_table_mac}")

        # Comparamos las direcciones MAC
        if arp_table_mac is None:
            # No se encontró una entrada para el router en la tabla ARP
            print("No se encontró una entrada para el router en la tabla ARP.")
        elif true_mac == arp_table_mac:
            # La tabla ARP no ha sido alterada
            print("La tabla ARP no ha sido modificada. La dirección MAC del router es correcta.")
        else:
            # La tabla ARP ha sido alterada
            print("¡ALERTA! La tabla ARP ha sido modificada. La dirección MAC del router ha sido falsificada.")
    except Exception as e:
        # Manejamos cualquier excepción e imprimimos el error
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 
