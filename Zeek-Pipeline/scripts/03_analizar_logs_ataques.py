import os
import pandas as pd

# Rutas base
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ZEEK_LOGS_DIR = os.path.join(BASE_DIR, "zeek_logs", "ataques")
INFORME_PATH = os.path.join(ZEEK_LOGS_DIR, "informe_logs_ataques.txt")

# Diccionario para almacenar resumen
resumen_logs = {}

# Recorre los subdirectorios (uno por cada traza de ataque)
for subdir in os.listdir(ZEEK_LOGS_DIR):
    ruta_subdir = os.path.join(ZEEK_LOGS_DIR, subdir)
    if os.path.isdir(ruta_subdir):
        for archivo in os.listdir(ruta_subdir):
            if archivo.endswith(".log"):
                ruta_log = os.path.join(ruta_subdir, archivo)
                try:
                    with open(ruta_log, "r") as f:
                        lineas = f.readlines()
                    
                    # Extrae nombres de columnas desde línea #fields
                    campos = None
                    for l in lineas:
                        if l.startswith("#fields"):
                            campos = l.strip().split("\t")[1:]
                            break

                    # Si no se encontraron campos, omitir
                    if not campos:
                        continue

                    # Carga en DataFrame
                    df = pd.read_csv(ruta_log, sep="\t", comment="#", names=campos)
                    n_registros = len(df)
                    muestra = df.head(2).to_string(index=False)

                    resumen_logs.setdefault(archivo, {
                        "total": 0,
                        "columnas": campos,
                        "muestras": []
                    })
                    resumen_logs[archivo]["total"] += n_registros
                    resumen_logs[archivo]["muestras"].append(muestra)

                except Exception as e:
                    print(f"Error leyendo {ruta_log}: {e}")

# Escribe informe en .txt
with open(INFORME_PATH, "w") as out:
    for log, info in resumen_logs.items():
        out.write(f"LOG: {log}\n")
        out.write(f"Total registros: {info['total']}\n")
        out.write(f"Columnas: {', '.join(info['columnas'])}\n")
        out.write("Ejemplo de registros:\n")
        for muestra in info["muestras"][:3]:
            out.write(muestra + "\n")
        out.write("-" * 60 + "\n\n")

print(f"Informe generado en: {INFORME_PATH}")
