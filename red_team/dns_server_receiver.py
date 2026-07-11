# dns_server_receiver.py (Ejecutar en tu PC principal: 192.168.1.14)
from scapy.all import *

DOMINIO_FALSO = "beacon.falso.local"
PUERTO_DNS = 53

def procesar_paquete_dns(pkt):
    # Verificamos si es una consulta DNS entrante
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        qname = pkt.getlayer(DNS).qd.qname.decode('utf-8')
        print(f"[+] Petición DNS recibida para: {qname}")

        if DOMINIO_FALSO in qname:
            # Comando simulado inocente que enviaremos en el TXT
            comando_simulado = "CMD_SIM:Show-Alert:Conexion_C2_Detectada_Correctamente"
            
            # Lo convertimos a hexadecimal para asegurar que viaje limpio
            payload_hex = comando_simulado.encode('utf-8').hex()
            
            # Construimos la respuesta DNS de tipo TXT (16)
            respuesta = DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(
                    name=qname,
                    type=16, # Registro TXT
                    ttl=10,
                    rdata=payload_hex
                )
            )
            
            # Devolvemos la respuesta a la IP origen de la máquina virtual
            send(IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=PUERTO_DNS)/respuesta, verbose=0)
            print(f"[*] Respuesta TXT enviada con payload simulado.")

print(f"[*] Escuchando peticiones DNS en el puerto {PUERTO_DNS}...")
# Sniffer de Scapy en la interfaz de red
sniff(filter=f"udp port {PUERTO_DNS}", prn=procesar_paquete_dns, store=0)