import json
from pathlib import Path
from typing import Union, List, Dict, Any, Optional
from datetime import datetime
import uuid


class EnhancedAttackMapper:
    """
    etiqueta ml --> tecnicas MITRE --> Indiciduos onologicos
    """
    
    def __init__(self, dict_path: Union[str, Path]):
        """
        Inicializa el mapper con el diccionario de mapeo existente.
        
        Args:
            dict_path: Ruta al archivo mapping_dict.json
        """
        with open(dict_path, encoding="utf-8") as fp:
            self.lookup: Dict[str, List[Dict[str, str]]] = json.load(fp)
        
        # Cache para evitar recálculos
        self._technique_cache = {}
        self._populate_technique_cache()
    
    def _populate_technique_cache(self):
        """
        Crea un cache de todas las técnicas únicas para acceso rápido.
        """
        for label, techniques in self.lookup.items():
            for tech in techniques:
                tech_id = tech['idTecnica']
                if tech_id not in self._technique_cache:
                    self._technique_cache[tech_id] = {
                        'id': tech_id,
                        'name': tech['nombreTecnica'],  # Nombre MITRE original
                        'tactic': tech['tactica'],      # Táctica MITRE original
                        'associated_labels': []
                    }
                self._technique_cache[tech_id]['associated_labels'].append(label)
    
    def map(self, label: str, confidence: float) -> List[Dict[str, Any]]:
        """
        Funcionalidad: mapea label del modelo a técnicas ATT&CK.
        CASO ESPECIAL: "Normal" devuelve lista vacía (sin técnicas).
        
        Args:
            label: Etiqueta devuelta por el modelo ML
            confidence: Confianza de la predicción (0.0 - 1.0)
            
        Returns:
            Lista de técnicas con información enriquecida (vacía si es Normal)
            
        Raises:
            KeyError: Si el label no existe en el diccionario
        """
        if label not in self.lookup:
            raise KeyError(f"{label} fuera del diccionario de mapeo")

        # CASO ESPECIAL: Comportamiento normal - NO hay técnicas de ataque
        if label == "Normal" or len(self.lookup[label]) == 0:
            return []  # Lista vacía - sin técnicas

        # CASO NORMAL: Técnicas de ataque
        techniques = []
        for tech in self.lookup[label]:
            enriched = tech.copy()
            enriched["model_label"] = label
            enriched["confidence"] = round(confidence, 3)
            techniques.append(enriched)
        return techniques
    
    def map_to_ontology_individuals(self, label: str, confidence: float, 
                                  detection_timestamp: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Mapea predicciones ML a individuos preparados para la ontología.
        MANEJA CASO ESPECIAL: "Normal" no genera AmenazaDetectada.
        
        Args:
            label: Etiqueta del modelo ML
            confidence: Confianza de la predicción
            detection_timestamp: Momento de la detección 
            
        Returns:
            Lista de individuos ontológicos estructurados (vacía si es Normal)
        """
        if detection_timestamp is None:
            detection_timestamp = datetime.now()
        
        # CASO ESPECIAL: Comportamiento normal - NO crear AmenazaDetectada
        if label == "Normal" or (label in self.lookup and len(self.lookup[label]) == 0):
            return [{
                'tipo': 'comportamiento_normal',
                'etiqueta': label,
                'confianza': confidence,
                'timestamp': detection_timestamp.isoformat(),
                'mensaje': 'Comportamiento normal detectado - No se requiere acción'
            }]
        
        # CASO NORMAL: Crear AmenazaDetectada para ataques
        base_techniques = self.map(label, confidence)
        
        ontology_individuals = []
        for tech in base_techniques:
            individual = self._create_amenaza_detectada_individual(tech, detection_timestamp)
            ontology_individuals.append(individual)
        
        return ontology_individuals
    
    def _create_amenaza_detectada_individual(self, technique: Dict[str, Any], 
                                           timestamp: datetime) -> Dict[str, Any]:
        """
        Crea un individual de AmenazaDetectada para la ontología.
        
        Args:
            technique: Información de la técnica detectada
            timestamp: Momento de la detección
            
        Returns:
            Diccionario con estructura ontológica
        """
        amenaza_id = f"Amenaza_{uuid.uuid4().hex[:8]}"
        technique_individual_id = f"{technique['idTecnica']}_{self._clean_name(technique['nombreTecnica'])}"
        tactic_individual_id = self._clean_name(technique['tactica'])
        
        return {
            'amenaza_id': amenaza_id,
            'tecnica': {
                'individual_id': technique_individual_id,
                'technique_id': technique['idTecnica'],
                'name': technique['nombreTecnica'],        # Nombre MITRE original
                'tactic': technique['tactica']             # Táctica MITRE original
            },
            'propiedades_deteccion': {
                'etiqueta_modelo': technique['model_label'],
                'confianza': technique['confidence'],
                'timestamp': timestamp.isoformat()
            },
            'relaciones_ontologia': {
                'tecnicaDetectada': technique_individual_id,
                'pertenece_a_tactica': tactic_individual_id,
                'tieneConfianza': technique['confidence'],
                'detectadaEn': timestamp.isoformat()
            }
        }
    
    def _clean_name(self, name: str) -> str:
        """
        Limpia nombres para IDs válidos en ontología - SIN espacios, SIN paréntesis, SIN acentos.
        
        Args:
            name: Nombre original
            
        Returns:
            Nombre limpio para ID
        """
        cleaned = name.replace(' ', '_').replace('-', '_').replace('/', '_')
        cleaned = cleaned.replace('(', '_').replace(')', '_').replace('&', 'and')
        cleaned = cleaned.replace('á', 'a').replace('é', 'e').replace('í', 'i')
        cleaned = cleaned.replace('ó', 'o').replace('ú', 'u').replace('ñ', 'n')
        # Eliminar dobles guiones bajos
        while '__' in cleaned:
            cleaned = cleaned.replace('__', '_')
        # Eliminar guiones bajos al final
        cleaned = cleaned.strip('_')
        return cleaned
    
    def get_unique_techniques(self) -> List[Dict[str, Any]]:
        """
        Obtiene todas las técnicas únicas del diccionario.
        Útil para poblar la ontología inicialmente.
        
        Returns:
            Lista de técnicas únicas con metadatos
        """
        return list(self._technique_cache.values())
    
    def get_unique_tactics(self) -> List[str]:
        """
        Obtiene todas las tácticas únicas del diccionario (nombres MITRE originales).
        
        Returns:
            Lista de tácticas únicas
        """
        tactics = set()
        for techniques in self.lookup.values():
            for tech in techniques:
                tactics.add(tech['tactica'])
        return sorted(list(tactics))
    
    def get_labels_by_technique(self, technique_id: str) -> List[str]:
        """
        Obtiene todos los labels del modelo asociados a una técnica específica.
        
        Args:
            technique_id: ID de la técnica (ej: "T0814")
            
        Returns:
            Lista de labels asociados a la técnica
        """
        if technique_id in self._technique_cache:
            return self._technique_cache[technique_id]['associated_labels']
        return []
    
    def export_ontology_structure(self) -> Dict[str, Any]:
        """
        Exporta la estructura completa preparada para crear la ontología.
        
        Returns:
            Diccionario con estructura completa para ontología
        """
        return {
            'techniques': self.get_unique_techniques(),
            'tactics': self.get_unique_tactics(),
            'model_labels': list(self.lookup.keys()),
            'mappings': self.lookup,
            'metadata': {
                'total_techniques': len(self._technique_cache),
                'total_tactics': len(self.get_unique_tactics()),
                'total_labels': len(self.lookup),
                'export_timestamp': datetime.now().isoformat(),
                'ontology_version': '2.0',
                'mitre_names': 'original',  # Confirmamos que usamos nombres MITRE originales
                'ontology_language': 'castellano',
                'nomenclature': 'clean'  # Sin espacios, sin paréntesis, sin acentos
            }
        }


def demo_enhanced_mapper():
    """
    Demo del EnhancedAttackMapper con nomenclatura limpia.
    """
    try:
        mapper = EnhancedAttackMapper("mapping_dict.json")
        
        # Demo mapeo original
        print("=== Demo Mapeo Original ===")
        result = mapper.map("ddos_http", 0.95)
        print(f"DDoS HTTP detectado con confianza 0.95:")
        for tech in result:
            print(f"  - {tech['idTecnica']}: {tech['nombreTecnica']} (Táctica: {tech['tactica']})")
        
        # Demo comportamiento normal
        print("\n=== Demo Comportamiento Normal ===")
        try:
            normal_result = mapper.map("Normal", 0.92)
            print(f"Comportamiento normal - Técnicas detectadas: {len(normal_result)}")
            if len(normal_result) == 0:
                print("Correcto: Normal no mapea a técnicas de ataque")
            else:
                print("Error: Normal no debería mapear a técnicas")
                
            # Demo ontológico para Normal
            normal_ontology = mapper.map_to_ontology_individuals("Normal", 0.92)
            print(f"Individuos ontológicos para Normal:")
            if normal_ontology[0]['tipo'] == 'comportamiento_normal':
                print(f" Tipo: {normal_ontology[0]['tipo']}")
                print(f" Mensaje: {normal_ontology[0]['mensaje']}")
            else:
                print("Error: Normal genera AmenazaDetectada incorrectamente")
                
        except KeyError:
            print("'Normal' no encontrado en mapping_dict.json")
            print(" Añade: '\"Normal\": [],' al inicio de tu mapping_dict.json")
        
        # Demo mapeo ontológico
        print("\n=== Demo Mapeo Ontológico (AmenazaDetectada) ===")
        ontology_result = mapper.map_to_ontology_individuals("port_scan", 0.87)
        print(f"Port scan detectado - Individual ontológico:")
        print(f"  ID Amenaza: {ontology_result[0]['amenaza_id']}")
        print(f"  Técnica MITRE: {ontology_result[0]['tecnica']['name']}")
        print(f"  Táctica MITRE: {ontology_result[0]['tecnica']['tactic']}")
        print(f"  ID técnica limpio: {ontology_result[0]['tecnica']['individual_id']}")
        
        # Demo función _clean_name
        print("\n=== Demo Función _clean_name ===")
        test_names = [
            "Remote System Discovery",
            "Data Destruction (T0809)",
            "Adversary-in-the-Middle",
            "Técnica con acentós"
        ]
        
        for name in test_names:
            clean = mapper._clean_name(name)
            print(f"  '{name}' → '{clean}'")
        
        # Demo tácticas MITRE originales
        print("\n=== Demo Tácticas MITRE Originales ===")
        tactics = mapper.get_unique_tactics()
        print(f"Tácticas MITRE (originales): {tactics}")
        
        # Demo estructura ontológica
        print("\n=== Demo Estructura Ontológica ===")
        structure = mapper.export_ontology_structure()
        print(f"Técnicas únicas: {structure['metadata']['total_techniques']}")
        print(f"Tácticas únicas: {structure['metadata']['total_tactics']}")
        print(f"Labels del modelo: {structure['metadata']['total_labels']}")
        print(f"Nombres MITRE: {structure['metadata']['mitre_names']}")
        print(f"Idioma ontología: {structure['metadata']['ontology_language']}")
        print(f"Nomenclatura: {structure['metadata']['nomenclature']}")
        
        print("\nEnhanced Mapper funcionando correctamente!")
        print("Nomenclatura limpia: MITRE original + Ontología sin espacios/acentos")
        return True
        
    except Exception as e:
        print(f"Error en Enhanced Mapper: {e}")
        return False


if __name__ == "__main__":
    demo_enhanced_mapper()