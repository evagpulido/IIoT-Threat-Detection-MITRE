import json
from pathlib import Path
from typing import Union, List, Dict, Any, Optional
from datetime import datetime
import uuid


class EnhancedAttackMapper:
    """
    etiqueta ml --> tecnicas MITRE 
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


