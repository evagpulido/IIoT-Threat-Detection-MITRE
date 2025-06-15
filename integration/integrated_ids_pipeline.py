import sys
import os
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
sys.path.append(os.path.join(project_root, 'mapping'))

from enhanced_mapper import EnhancedAttackMapper
from amenaza_creator import AmenazaCreator
from datetime import datetime
from typing import Dict, List, Any
import pickle
import pandas as pd
import numpy as np


class MLHandler:
    """
    Maneja modelos ML para el sistema IDS.
    Carga modelos entrenados y realiza predicciones sobre muestras del dataset.
    """
    
    def __init__(self, 
                 binary_model_path: str = "./models/modelo_RandomForest.pkl",
                 multi_model_path: str = "./models/modelo_RandomForest_multi.pkl", 
                 train_test_data_path: str = "./data/train_test_data.pkl"):
        """
        Inicializa el manejador ML del sistema IDS.
        """
        print(" Cargando modelos ML...")
        self.binary_model = self._load_model(binary_model_path, "Modelo Binario")
        self.multi_model = self._load_model(multi_model_path, "Modelo Multiclase")
        
        print(" Cargando datos de test...")
        self.test_data = self._load_test_data(train_test_data_path)
        
        print(" Modelos ML cargados correctamente")
        
    def _load_model(self, model_path: str, model_name: str):
        """Carga un modelo desde archivo pickle."""
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            print(f" {model_name} cargado: {type(model).__name__}")
            return model
        except Exception as e:
            print(f" Error cargando {model_name}: {e}")
            return None
    
    def _load_test_data(self, data_path: str) -> Dict:
        """Carga los datos de test desde pickle."""
        try:
            with open(data_path, 'rb') as f:
                data = pickle.load(f)
            
            print(f" Datos cargados:")
            for key in data.keys():
                if hasattr(data[key], 'shape'):
                    print(f"  - {key}: {data[key].shape}")
            
            return data
        except Exception as e:
            print(f" Error cargando datos: {e}")
            return {}
    
    def predict_sample(self, sample_index: int) -> Dict[str, Any]:
        """
        Predice una muestra específica usando los modelos entrenados.
        Realiza predicción binaria (ataque/normal) y multiclase (tipo de ataque).
        """
        if not self.binary_model or not self.multi_model or not self.test_data:
            return {"error": "Modelos o datos no cargados correctamente"}
        
        try:
            # Obtener muestra
            X_test = self.test_data['X_test_original']
            y_test_bin = self.test_data['y_test_bin']
            y_test_multi = self.test_data['y_test_multi']
            
            if sample_index >= len(X_test):
                return {"error": f"Índice {sample_index} fuera de rango (max: {len(X_test)-1})"}
            
            sample = X_test.iloc[sample_index:sample_index+1]
            true_bin = y_test_bin.iloc[sample_index]
            true_multi = y_test_multi.iloc[sample_index]
            
            # Predicción binaria
            bin_pred = self.binary_model.predict(sample)[0]
            bin_proba = self.binary_model.predict_proba(sample)[0]
            bin_confidence = float(max(bin_proba))
            
            # Predicción multiclase (solo si se predijo ataque)
            if bin_pred == 1:  # Es ataque
                multi_pred = self.multi_model.predict(sample)[0]
                multi_proba = self.multi_model.predict_proba(sample)[0]
                multi_confidence = float(max(multi_proba))
                final_label = multi_pred
                final_confidence = multi_confidence
            else:  # No es ataque
                multi_pred = "Normal"
                multi_proba = bin_proba
                final_label = "Normal"
                final_confidence = bin_confidence
            
            return {
                'sample_index': sample_index,
                'ground_truth': {
                    'binary': int(true_bin),
                    'multiclass': true_multi
                },
                'binary_prediction': {
                    'predicted': int(bin_pred),
                    'confidence': bin_confidence,
                    'probabilities': bin_proba.tolist()
                },
                'multiclass_prediction': {
                    'predicted': final_label,
                    'confidence': final_confidence,
                    'probabilities': multi_proba.tolist()
                },
                'final_label': final_label,
                'final_confidence': final_confidence
            }
            
        except Exception as e:
            return {"error": f"Error en predicción: {e}"}


class IntegratedIDSPipeline:
    """
    Pipeline IDS completo para Industrial IoT:
    1. Procesa muestras del dataset con modelos ML entrenados
    2. Crea individuos AmenazaDetectada en la ontología 
    3. Conecta automáticamente: Ataque → Técnica → Táctica → Mitigación
    """
    
    def __init__(self):
        """Inicializa el pipeline IDS integrado."""
        print(" Inicializando Pipeline IDS Integrado...")
        
        # Manejador ML
        self.ml_handler = MLHandler()
        
        # Mapper para ML → MITRE
        self.mapper = EnhancedAttackMapper("./mapping/mapping_dict.json")
        
        # Creador de amenazas ontológicas
        self.amenaza_creator = AmenazaCreator()
        
        print(" Pipeline IDS Integrado listo")
    
    def process_sample_complete(self, sample_index: int) -> Dict[str, Any]:
        """
        Procesa una muestra completa del dataset: ML → Ontología → AmenazaDetectada.
        
        Args:
            sample_index: Índice de la muestra en el dataset de test
            
        Returns:
            Diccionario con resultados completos del procesamiento
        """
        print(f"\n Procesando muestra {sample_index} completa...")
    
        # 1. PREDICCIÓN ML
        ml_result = self.ml_handler.predict_sample(sample_index)
        
        if "error" in ml_result:
            return {"error": f"Error ML: {ml_result['error']}"}
        
        # 2. MAPEO A MITRE (solo si necesario)
        final_label = ml_result['final_label']
        final_confidence = ml_result['final_confidence']
        
        mitre_techniques = []
        if final_label != "Normal":
            try:
                mitre_techniques = self.mapper.map(final_label, final_confidence)
            except KeyError:
                print(f" Label '{final_label}' no encontrado en mapping MITRE")
        
        # 3. CREAR AMENAZA EN ONTOLOGÍA (si es ataque)
        amenaza_uri = None
        ontology_created = False
        
        if final_label != "Normal":
            try:
                amenaza_uri = self.amenaza_creator.create_amenaza_detectada(
                    ml_result, sample_index
                )
                ontology_created = True
                print(f" Amenaza creada en ontología: {amenaza_uri}")
            except Exception as e:
                print(f" Error creando amenaza: {e}")
                ontology_created = False
        else:
            print(f" Comportamiento normal - No se crea amenaza")
        
        # 4. OBTENER INFORMACIÓN ONTOLÓGICA COMPLETA
        ontology_info = self._get_ontology_info(amenaza_uri, final_label)
        
        # 5. RESULTADO INTEGRADO
        complete_result = {
            'sample_info': {
                'index': sample_index,
                'timestamp': datetime.now().isoformat(),
                'pipeline_version': 'IDS_Integrado_v1.0'
            },
            'ml_stage': ml_result,
            'mitre_stage': {
                'techniques_found': len(mitre_techniques),
                'techniques': mitre_techniques
            },
            'ontology_stage': {
                'amenaza_created': ontology_created,
                'amenaza_uri': str(amenaza_uri) if amenaza_uri else None,
                'ontology_info': ontology_info
            },
            'summary': self._generate_summary(ml_result, ontology_info, ontology_created)
        }
        
        return complete_result
    
    def _get_ontology_info(self, amenaza_uri: str, attack_label: str) -> Dict[str, Any]:
        """
        Obtiene información completa de la ontología para una amenaza detectada.
        
        Args:
            amenaza_uri: URI del individuo AmenazaDetectada creado
            attack_label: Etiqueta del ataque detectado
            
        Returns:
            Diccionario con información ontológica estructurada
        """
        if not amenaza_uri or attack_label == "Normal":
            return {
                'type': 'normal_behavior',
                'attack_type': None,
                'techniques': [],
                'tactics': [],
                'mitigations': []
            }
        
        try:
            # 1. Consulta básica: ataque, técnicas y tácticas (siempre existen)
            basic_query = f"""
            PREFIX ids: <{self.amenaza_creator.namespace}>
            SELECT DISTINCT 
                ?ataque ?ataqueNombre
                ?tecnica ?tecnicaID ?tecnicaNombre 
                ?tactica ?tacticaNombre
            WHERE {{
                <{amenaza_uri}> ids:esAtaque ?ataque .
                ?ataque ids:tieneNombre ?ataqueNombre .
                
                <{amenaza_uri}> ids:utilizaTecnica ?tecnica .
                ?tecnica ids:tieneID ?tecnicaID .
                ?tecnica ids:tieneNombre ?tecnicaNombre .
                
                <{amenaza_uri}> ids:utilizaTactica ?tactica .
                ?tactica ids:tieneNombre ?tacticaNombre .
            }}
            """
            
            basic_results = self.amenaza_creator.graph.query(basic_query)
            
            # Procesar resultados básicos
            attack_info = None
            techniques = []
            tactics = []
            
            for row in basic_results:
                # Información del ataque (solo una vez)
                if not attack_info:
                    attack_info = {
                        'uri': str(row.ataque),
                        'name': str(row.ataqueNombre)
                    }
                
                # Técnicas
                technique_info = {
                    'uri': str(row.tecnica),
                    'id': str(row.tecnicaID),
                    'name': str(row.tecnicaNombre)
                }
                if technique_info not in techniques:
                    techniques.append(technique_info)
                
                # Tácticas
                tactic_info = {
                    'uri': str(row.tactica),
                    'name': str(row.tacticaNombre)
                }
                if tactic_info not in tactics:
                    tactics.append(tactic_info)
            
            # 2. Consulta separada para mitigaciones (pueden no existir)
            mitigations = []
            try:
                mitigation_query = f"""
                PREFIX ids: <{self.amenaza_creator.namespace}>
                SELECT DISTINCT 
                    ?mitigacion ?mitigacionID ?mitigacionNombre ?mitigacionDesc
                WHERE {{
                    <{amenaza_uri}> ids:mitigacionRecomendada ?mitigacion .
                    ?mitigacion ids:tieneID ?mitigacionID .
                    ?mitigacion ids:tieneNombre ?mitigacionNombre .
                    ?mitigacion ids:tieneDescripcion ?mitigacionDesc .
                }}
                """
                
                mitigation_results = self.amenaza_creator.graph.query(mitigation_query)
                
                for row in mitigation_results:
                    mitigation_info = {
                        'uri': str(row.mitigacion),
                        'id': str(row.mitigacionID),
                        'name': str(row.mitigacionNombre),
                        'description': str(row.mitigacionDesc)
                    }
                    if mitigation_info not in mitigations:
                        mitigations.append(mitigation_info)
                        
            except Exception as e:
                print(f" No se encontraron mitigaciones para esta amenaza: {e}")
                mitigations = []
            
            return {
                'type': 'threat_detected',
                'attack_type': attack_info,
                'techniques': techniques,
                'tactics': tactics,
                'mitigations': mitigations
            }
            
        except Exception as e:
            print(f" Error consultando ontología: {e}")
            return {
                'type': 'error',
                'error': str(e),
                'attack_type': None,
                'techniques': [],
                'tactics': [],
                'mitigations': []
            }
    
    def _generate_summary(self, ml_result: Dict, ontology_info: Dict, ontology_created: bool) -> Dict[str, Any]:
        """
        Genera resumen ejecutivo del procesamiento de la muestra.
        
        Args:
            ml_result: Resultados de la predicción ML
            ontology_info: Información extraída de la ontología
            ontology_created: Si se creó un individuo AmenazaDetectada
            
        Returns:
            Resumen estructurado con información clave
        """
        
        if ml_result['final_label'] == "Normal":
            return {
                'type': 'normal_behavior',
                'message': 'Comportamiento normal detectado - No se requiere acción',
                'confidence': ml_result['final_confidence'],
                'action_required': False
            }
        
        # Para ataques
        summary = {
            'type': 'threat_detected',
            'attack_type': ml_result['final_label'],
            'confidence': ml_result['final_confidence'],
            'action_required': True,
            'ontology_integrated': ontology_created
        }
        
        if ontology_info['type'] == 'threat_detected':
            summary.update({
                'techniques_count': len(ontology_info['techniques']),
                'tactics_count': len(ontology_info['tactics']),
                'mitigations_available': len(ontology_info['mitigations']),
                'immediate_actions': [m['name'] for m in ontology_info['mitigations'][:3]]
            })
        
        return summary
    
    def process_random_samples(self, num_samples: int = 5) -> List[Dict[str, Any]]:
        """
        Procesa un conjunto de muestras aleatorias del dataset de test.
        
        Args:
            num_samples: Número de muestras aleatorias a procesar
            
        Returns:
            Lista con resultados del procesamiento de cada muestra
        """
        import random
        
        # Obtener tamaño del dataset de test
        X_test_size = len(self.ml_handler.test_data['X_test_original'])
        
        # Generar índices aleatorios
        random_indices = random.sample(range(X_test_size), min(num_samples, X_test_size))
        
        print(f"\n Procesando {len(random_indices)} muestras aleatorias del X_test...")
        print(f" Índices seleccionados: {random_indices}")
        print(f" Dataset size: {X_test_size} muestras")
        
        results = []
        threats_created = 0
        normal_behavior = 0
        
        for i, sample_index in enumerate(random_indices):
            print(f"\n Muestra {i+1}/{len(random_indices)} (índice {sample_index})...")
            
            # FLUJO COMPLETO: X_test → ML → Ontología
            result = self.process_sample_complete(sample_index)
            results.append(result)
            
            # Contadores
            if result.get('summary', {}).get('type') == 'threat_detected':
                threats_created += 1
            elif result.get('summary', {}).get('type') == 'normal_behavior':
                normal_behavior += 1
        
        print(f"\n Resumen del procesamiento aleatorio:")
        print(f"  - Amenazas detectadas y creadas: {threats_created}")
        print(f"  - Comportamiento normal: {normal_behavior}")
        print(f"  - Total procesado: {len(results)}")
        
        return results
    
    def save_ontology_with_threats(self, output_path: str = None) -> str:
        """Guarda la ontología actualizada con las amenazas creadas."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"./ontology/ids_iiot_ontologia_with_threats_{timestamp}.owl"
        
        saved_path = self.amenaza_creator.save_updated_ontology(output_path)
        print(f" Ontología con amenazas guardada: {saved_path}")
        return saved_path


def main():
    """
    Demostración completa del pipeline IDS integrado.
    Procesa muestras individuales y aleatorias, y guarda la ontología resultante.
    """
    print(" Demostrando Pipeline IDS Integrado...")
    
    try:
        # Inicializar pipeline
        ids_pipeline = IntegratedIDSPipeline()
        
        # Demo 1: Procesar muestra individual
        #print("\n=== Demo 1: Procesamiento de Muestra Individual ===")
        #result = ids_pipeline.process_sample_complete(0)
        
        #if "error" not in result:
        #    summary = result['summary']
            # print(f" Muestra procesada:")
            # print(f"  - Tipo: {summary['type']}")
            # print(f"  - Ataque: {summary.get('attack_type', 'N/A')}")
            # print(f"  - Confianza: {summary['confidence']:.3f}")
            # print(f"  - Ontología integrada: {summary.get('ontology_integrated', False)}")
            
            # if summary.get('mitigations_available', 0) > 0:
            #     print(f"  - Mitigaciones: {summary['mitigations_available']}")
            #     print(f"  - Acciones inmediatas: {summary.get('immediate_actions', [])}")
        
        # Demo 2: Procesar muestras aleatorias
        print("\n=== Demo 2: Procesamiento de 3 Muestras Aleatorias ===")
        random_results = ids_pipeline.process_random_samples(num_samples=3)
        
        # Demo 3: Guardar ontología poblada
        print("\n=== Demo 3: Guardar Ontología Poblada ===")
        saved_path = ids_pipeline.save_ontology_with_threats()
        
        print(f"\n Pipeline IDS Integrado funcionando correctamente!")
        print(f" Sistema completo: Dataset → ML → MITRE → Ontología")
        print(f" Ontología poblada guardada en: {saved_path}")
        
        return True
        
    except Exception as e:
        print(f" Error en pipeline: {e}")
        return False


if __name__ == "__main__":
    main()