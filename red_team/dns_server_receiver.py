import socket
import argparse
import logging
from scapy.all import DNS, DNSRR

# A. Configuración de Logging profesional
logging.basicConfig(
    level=logging.INFO, 
    format='[%(asctime)s] [%(levelname)s] %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)

# C. Banner ASCII
BANNER = """
 ____  _   _ ____    ____ ____    ___        _ 
|  _ \\| \\ | / ___|  / ___|___ \\  |  _ \\ ___ | |
| | | |  \\| \\___ \\ | |     __) | | |_) / _ \\| |
| |_| | |\\  |___) || |___ / __/  |  __/ (_) | |
|____/|_| \\_|____/  \\____|_____| |_|   \\___/|_|
      -- DNS Tunneling PoC Server --
"""

def start_server(ip_escucha, puerto, dominio):
    print(BANNER)
    logging.info("Iniciando Servidor C2 Simulado...")
    logging.info(f"Escuchando en {ip_escucha}:{puerto} para el dominio '{dominio}'")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip_escucha, puerto))
    except Exception as e:
        logging.error(f"Error al abrir el puerto {puerto}: {e}")
        return

    while True:
        try:
            datos, direccion_cliente = sock.recvfrom(1024)
            pkt_dns = DNS(datos)
            
            if pkt_dns.qd:
                qname = pkt_dns.qd.qname.decode('utf-8')
                
                if dominio in qname:
                    logging.info(f"Petición DNS interceptada desde {direccion_cliente[0]} para: {qname}")
                    
                    # Payload inofensivo para la PoC
                    comando_simulado = "CMD_SIM:Show-Alert:Conexion_C2_Detectada_Correctamente"
                    payload_hex = comando_simulado.encode('utf-8').hex()
                    
                    respuesta_dns = DNS(
                        id=pkt_dns.id,
                        qr=1,
                        aa=1,
                        qd=pkt_dns.qd,
                        an=DNSRR(
                            rrname=qname,
                            type=16, # Registro TXT
                            ttl=10,
                            rdata=payload_hex
                        )
                    )
                    sock.sendto(bytes(respuesta_dns), direccion_cliente)
                    logging.info(f"Respuesta TXT enviada con payload simulado a {direccion_cliente[0]}")
                    
        except Exception as e:
            logging.error(f"Error procesando paquete: {e}")

if __name__ == "__main__":
    # B. Argumentos por línea de comandos
    parser = argparse.ArgumentParser(description="DNS Tunneling C2 Server PoC")
    parser.add_argument("-i", "--ip", default="0.0.0.0", help="IP de escucha (default: 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=9000, help="Puerto UDP (default: 9000)")
    parser.add_argument("-d", "--domain", default="beacon.falso.local", help="Dominio objetivo (default: beacon.falso.local)")
    
    args = parser.parse_args()
    start_server(args.ip, args.port, args.domain)