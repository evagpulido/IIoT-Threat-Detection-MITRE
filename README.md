# Sistema de Detección de Intrusiones para Industrial IoT basado en Machine Learning y MITRE ATT&CK

## Descripción del Proyecto

Este proyecto presenta un sistema de detección de intrusiones (IDS) diseñado para entornos Industrial Internet of Things (IIoT). El sistema utiliza técnicas de Machine Learning para identificar amenazas y las clasifica según el framework MITRE ATT&CK for ICS, integrando los resultados en una ontología semántica.

## Objetivos

- Detección automatizada de intrusiones en redes IIoT
- Clasificación de amenazas según framework MITRE ATT&CK for ICS
- Integración ontológica para representación del conocimiento de seguridad
- Propuesta automatizada de mitigaciones basadas en TTPs detectadas

## Dependencias Python:
pip install pandas numpy scikit-learn matplotlib owlready2 imbalanced-learn jupyter

## Instalacion
### Clonar el repositorio
git clone [URL-del-repositorio]
cd IIoT-Threat-Detection-MITRE

## Demostración Rápida
Para ejecutar el sistema con modelos pre-entrenados:
### Crear ontología base
python3 ontology/ontology_populator.py
### Ejecutar pipeline completo
python3 integration/integrated_ids_pipeline.py

## Ejecución Completa
Para procesar datos desde capturas de tráfico:

### 1. Procesar capturas con Zeek
python3 Zeek-Pipeline/scripts/01_procesar_pcap_con_zeek.py

### 2. Crear dataset
jupyter notebook notebooks/creacion_dataset_NG-IIoTset.ipynb

### 3. Preprocesar datos
jupyter notebook notebooks/preprocess_NG-IIoTset.ipynb

### 4. Entrenar modelos
jupyter notebook notebooks/entrenamiento.ipynb

### 5. Crear ontología base
python3 ontology/ontology_populator.py

### 6. Ejecutar pipeline integrado
python3 integration/integrated_ids_pipeline.py
