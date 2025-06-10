import os
import subprocess

# Define rutas base
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PCAP_DIR = os.path.join(BASE_DIR, "pcaps")  #Zeek-Pipeline/pcaps
ZEEK_LOG_DIR = os.path.join(BASE_DIR, "zeek_logs")  #Zeek-Pipeline/zeek_logs

# Subdirectorios: 'normal' y 'ataques'
tipos_trafico = ["normal", "ataques"]

for tipo in tipos_trafico:
    pcap_subdir = os.path.join(PCAP_DIR, tipo) #Zeek-Pipeline/pcaps/normal
    logs_subdir = os.path.join(ZEEK_LOG_DIR, tipo)

    # Recorre todos los archivos .pcap del subdirectorio
    for pcap_file in os.listdir(pcap_subdir):
        if pcap_file.endswith(".pcap"):
            nombre_base = os.path.splitext(pcap_file)[0]
            pcap_path = os.path.join(pcap_subdir, pcap_file)
            output_path = os.path.join(logs_subdir, nombre_base)

            # Crea carpeta de salida si no existe
            os.makedirs(output_path, exist_ok=True)

            print(f"Procesando: {pcap_file} → {output_path}")

            # Ejecutar Zeek sobre el archivo
            subprocess.run(["zeek", "-r", pcap_path], cwd=output_path)
