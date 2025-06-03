import sys
import os
sys.path.append('../mapping')

from enhanced_mapper import EnhancedAttackMapper
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import json


class OntologyPopulator:
    """
    Genera ontología OWL con estructura correcta:
    Ataque, Tecnica, Tactica, Mitigacion, AmenazaDetectada
    """
    
    def __init__(self, mapping_dict_path: str, mitigations_dict_path: str = "../integration/mitigations_dict.json", output_dir: str = "."):
        """
        Inicializa el poblador de ontología.
        
        Args:
            mapping_dict_path: Ruta al mapping_dict.json
            mitigations_dict_path: Ruta al mitigations_dict.json
            output_dir: Directorio donde guardar los archivos .owl
        """
        self.mapper = EnhancedAttackMapper(mapping_dict_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Cargar mitigaciones
        self.mitigations_data = self._load_mitigations(mitigations_dict_path)
        
        # Namespace simplificado
        self.base_iri = "http://universidad.es/tfm/ids-iiot"
        self.ontology_iri = f"{self.base_iri}/ontologia"
        
    def _load_mitigations(self, mitigations_path: str) -> Dict:
        """Carga el diccionario de mitigaciones."""
        try:
            with open(mitigations_path, 'r', encoding='utf-8') as f:
                mitigations = json.load(f)
            print(f"✅ Mitigaciones MITRE cargadas: {len(mitigations)} técnicas")
            return mitigations
        except FileNotFoundError:
            print(f"❌ Archivo de mitigaciones no encontrado: {mitigations_path}")
            return {}
        except Exception as e:
            print(f"❌ Error cargando mitigaciones: {e}")
            return {}
        
    def generate_complete_ontology(self) -> str:
        """
        Genera la ontología completa con estructura correcta.
        
        Returns:
            Contenido OWL completo como string
        """
        owl_content = f'''<?xml version="1.0"?>
<rdf:RDF xmlns="http://universidad.es/tfm/ids-iiot/ontologia#"
     xml:base="http://universidad.es/tfm/ids-iiot/ontologia"
     xmlns:owl="http://www.w3.org/2002/07/owl#"
     xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
     xmlns:xml="http://www.w3.org/XML/1998/namespace"
     xmlns:xsd="http://www.w3.org/2001/XMLSchema#"
     xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#">
    
    <owl:Ontology rdf:about="http://universidad.es/tfm/ids-iiot/ontologia">
        <rdfs:label>Ontología IDS para IIoT</rdfs:label>
        <rdfs:comment>Sistema de Detección de Intrusiones para Industrial IoT basado en MITRE ATT&amp;CK</rdfs:comment>
        <owl:versionInfo>3.0</owl:versionInfo>
    </owl:Ontology>
    
    <!-- ==================== CLASES PRINCIPALES ==================== -->
    
    <owl:Class rdf:about="#Ataque">
        <rdfs:label>Ataque</rdfs:label>
        <rdfs:comment>Tipo de ataque detectado por el modelo ML (ddos_http, sql_injection, etc.)</rdfs:comment>
    </owl:Class>
    
    <owl:Class rdf:about="#Tecnica">
        <rdfs:label>Tecnica</rdfs:label>
        <rdfs:comment>Técnica de ataque según MITRE ATT&amp;CK for ICS</rdfs:comment>
    </owl:Class>
    
    <owl:Class rdf:about="#Tactica">
        <rdfs:label>Tactica</rdfs:label>
        <rdfs:comment>Táctica de ataque según MITRE ATT&amp;CK for ICS</rdfs:comment>
    </owl:Class>
    
    <owl:Class rdf:about="#Mitigacion">
        <rdfs:label>Mitigacion</rdfs:label>
        <rdfs:comment>Medida de mitigación según MITRE ATT&amp;CK for ICS</rdfs:comment>
    </owl:Class>
    
    <owl:Class rdf:about="#AmenazaDetectada">
        <rdfs:label>AmenazaDetectada</rdfs:label>
        <rdfs:comment>Instancia específica de amenaza detectada por el sistema IDS</rdfs:comment>
    </owl:Class>
    
    <!-- ==================== PROPIEDADES OBJETO ==================== -->
    
    <!-- Relaciones de AmenazaDetectada -->
    <owl:ObjectProperty rdf:about="#esAtaque">
        <rdfs:label>esAtaque</rdfs:label>
        <rdfs:domain rdf:resource="#AmenazaDetectada"/>
        <rdfs:range rdf:resource="#Ataque"/>
        <rdfs:comment>Amenaza detectada es de un tipo específico de ataque</rdfs:comment>
    </owl:ObjectProperty>
    
    <owl:ObjectProperty rdf:about="#utilizaTecnica">
        <rdfs:label>utilizaTecnica</rdfs:label>
        <rdfs:domain rdf:resource="#AmenazaDetectada"/>
        <rdfs:range rdf:resource="#Tecnica"/>
        <rdfs:comment>Amenaza detectada utiliza técnica(s) específica(s) MITRE</rdfs:comment>
    </owl:ObjectProperty>
    
    <owl:ObjectProperty rdf:about="#utilizaTactica">
        <rdfs:label>utilizaTactica</rdfs:label>
        <rdfs:domain rdf:resource="#AmenazaDetectada"/>
        <rdfs:range rdf:resource="#Tactica"/>
        <rdfs:comment>Amenaza detectada utiliza táctica(s) específica(s) MITRE</rdfs:comment>
    </owl:ObjectProperty>
    
    <owl:ObjectProperty rdf:about="#mitigacion_recomendada">
        <rdfs:label>mitigacion_recomendada</rdfs:label>
        <rdfs:domain rdf:resource="#AmenazaDetectada"/>
        <rdfs:range rdf:resource="#Mitigacion"/>
        <rdfs:comment>Mitigación recomendada para la amenaza detectada</rdfs:comment>
    </owl:ObjectProperty>
    
    <!-- Relaciones estructurales -->
    <owl:ObjectProperty rdf:about="#implementa_tecnica">
        <rdfs:label>implementa_tecnica</rdfs:label>
        <rdfs:domain rdf:resource="#Ataque"/>
        <rdfs:range rdf:resource="#Tecnica"/>
        <rdfs:comment>Tipo de ataque implementa técnica(s) MITRE específica(s)</rdfs:comment>
    </owl:ObjectProperty>
    
    <owl:ObjectProperty rdf:about="#pertenece_a_tactica">
        <rdfs:label>pertenece_a_tactica</rdfs:label>
        <rdfs:domain rdf:resource="#Tecnica"/>
        <rdfs:range rdf:resource="#Tactica"/>
        <rdfs:comment>Técnica pertenece a una táctica específica</rdfs:comment>
    </owl:ObjectProperty>
    
    <owl:ObjectProperty rdf:about="#mitigada_por">
        <rdfs:label>mitigada_por</rdfs:label>
        <rdfs:domain rdf:resource="#Tecnica"/>
        <rdfs:range rdf:resource="#Mitigacion"/>
        <rdfs:comment>Técnica de ataque se mitiga con estrategia específica</rdfs:comment>
    </owl:ObjectProperty>
    
    <!-- ==================== PROPIEDADES DATOS ==================== -->
    
    <owl:DatatypeProperty rdf:about="#tieneID">
        <rdfs:label>tieneID</rdfs:label>
        <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#string"/>
        <rdfs:comment>Identificador único del elemento</rdfs:comment>
    </owl:DatatypeProperty>
    
    <owl:DatatypeProperty rdf:about="#tieneNombre">
        <rdfs:label>tieneNombre</rdfs:label>
        <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#string"/>
        <rdfs:comment>Nombre descriptivo del elemento</rdfs:comment>
    </owl:DatatypeProperty>
    
    <owl:DatatypeProperty rdf:about="#tieneDescripcion">
        <rdfs:label>tieneDescripcion</rdfs:label>
        <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#string"/>
        <rdfs:comment>Descripción detallada del elemento</rdfs:comment>
    </owl:DatatypeProperty>
    
    <!-- Propiedades específicas de AmenazaDetectada -->
    <owl:DatatypeProperty rdf:about="#tieneConfianza">
        <rdfs:label>tieneConfianza</rdfs:label>
        <rdfs:domain rdf:resource="#AmenazaDetectada"/>
        <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#decimal"/>
        <rdfs:comment>Nivel de confianza de la detección (0.0 - 1.0)</rdfs:comment>
    </owl:DatatypeProperty>
    
    <owl:DatatypeProperty rdf:about="#detectadaEn">
        <rdfs:label>detectadaEn</rdfs:label>
        <rdfs:domain rdf:resource="#AmenazaDetectada"/>
        <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#dateTime"/>
        <rdfs:comment>Momento en que se realizó la detección</rdfs:comment>
    </owl:DatatypeProperty>
    
    <owl:DatatypeProperty rdf:about="#indiceMuestra">
        <rdfs:label>indiceMuestra</rdfs:label>
        <rdfs:domain rdf:resource="#AmenazaDetectada"/>
        <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#integer"/>
        <rdfs:comment>Índice de la muestra del dataset que generó la detección</rdfs:comment>
    </owl:DatatypeProperty>
'''
        
        # Añadir individuos de tácticas
        owl_content += self._generate_tactics_individuals()
        
        # Añadir individuos de técnicas
        owl_content += self._generate_techniques_individuals()
        
        # Añadir individuos de ataques (antes etiquetas)
        owl_content += self._generate_attacks_individuals()
        
        # Añadir individuos de mitigaciones
        owl_content += self._generate_mitigations_individuals()
        
        # Añadir relaciones estructurales
        owl_content += self._generate_structural_relationships()
        
        owl_content += "\n</rdf:RDF>"
        return owl_content
    
    def _generate_tactics_individuals(self) -> str:
        """Genera individuos de tácticas."""
        tactics = self.mapper.get_unique_tactics()
        content = "\n    <!-- ==================== INDIVIDUOS TACTICAS ==================== -->\n"
        
        for tactic in tactics:
            tactic_clean = self._clean_name(tactic)
            content += f'''
    <owl:NamedIndividual rdf:about="#{tactic_clean}">
        <rdf:type rdf:resource="#Tactica"/>
        <tieneNombre rdf:datatype="http://www.w3.org/2001/XMLSchema#string">{tactic}</tieneNombre>
        <rdfs:label>{tactic_clean}</rdfs:label>
        <rdfs:comment>Táctica MITRE ATT&amp;CK for ICS</rdfs:comment>
    </owl:NamedIndividual>
'''
        return content
    
    def _generate_techniques_individuals(self) -> str:
        """Genera individuos de técnicas."""
        techniques = self.mapper.get_unique_techniques()
        content = "\n    <!-- ==================== INDIVIDUOS TECNICAS ==================== -->\n"
        
        for tech in techniques:
            tech_clean = f"{tech['id']}"
            content += f'''
    <owl:NamedIndividual rdf:about="#{tech_clean}">
        <rdf:type rdf:resource="#Tecnica"/>
        <tieneID rdf:datatype="http://www.w3.org/2001/XMLSchema#string">{tech['id']}</tieneID>
        <tieneNombre rdf:datatype="http://www.w3.org/2001/XMLSchema#string">{tech['name']}</tieneNombre>
        <rdfs:label>{tech_clean}</rdfs:label>
        <rdfs:comment>Técnica MITRE ATT&amp;CK for ICS</rdfs:comment>
    </owl:NamedIndividual>
'''
        return content
    
    def _generate_attacks_individuals(self) -> str:
        """Genera individuos de tipos de ataque (antes etiquetas)."""
        labels = list(self.mapper.lookup.keys())
        content = "\n    <!-- ==================== INDIVIDUOS ATAQUES ==================== -->\n"
        
        for label in labels:
            # Saltar "Normal" ya que no es un ataque
            if label == "Normal":
                continue
                
            attack_clean = f"{self._clean_name(label)}"
            content += f'''
    <owl:NamedIndividual rdf:about="#{attack_clean}">
        <rdf:type rdf:resource="#Ataque"/>
        <tieneNombre rdf:datatype="http://www.w3.org/2001/XMLSchema#string">{label}</tieneNombre>
        <rdfs:label>{attack_clean}</rdfs:label>
        <rdfs:comment>Tipo de ataque detectado por el modelo ML</rdfs:comment>
    </owl:NamedIndividual>
'''
        return content
    
    def _generate_mitigations_individuals(self) -> str:
        """Genera individuos de mitigaciones MITRE."""
        if not self.mitigations_data:
            return "\n    <!-- Sin mitigaciones disponibles -->\n"
            
        content = "\n    <!-- ==================== INDIVIDUOS MITIGACIONES ==================== -->\n"
        
        # Recopilar todas las mitigaciones únicas
        unique_mitigations = {}
        
        for technique_id, technique_data in self.mitigations_data.items():
            for mitigation in technique_data['mitigations']:
                mit_id = mitigation['id']
                if mit_id not in unique_mitigations:
                    unique_mitigations[mit_id] = {
                        'id': mit_id,
                        'name': mitigation['name'],
                        'description': mitigation['description']
                    }
        
        # Generar individuos únicos
        for mit_id, mitigation in unique_mitigations.items():
            mit_clean = f"{mit_id}"
            content += f'''
    <owl:NamedIndividual rdf:about="#{mit_clean}">
        <rdf:type rdf:resource="#Mitigacion"/>
        <tieneID rdf:datatype="http://www.w3.org/2001/XMLSchema#string">{mitigation['id']}</tieneID>
        <tieneNombre rdf:datatype="http://www.w3.org/2001/XMLSchema#string">{mitigation['name']}</tieneNombre>
        <tieneDescripcion rdf:datatype="http://www.w3.org/2001/XMLSchema#string">{mitigation['description']}</tieneDescripcion>
        <rdfs:label>{mit_clean}</rdfs:label>
        <rdfs:comment>Mitigación MITRE ATT&amp;CK for ICS</rdfs:comment>
    </owl:NamedIndividual>
'''
        return content
    
    def _generate_structural_relationships(self) -> str:
        """Genera todas las relaciones estructurales."""
        content = "\n    <!-- ==================== RELACIONES ESTRUCTURALES ==================== -->\n"
        
        # Relaciones técnica → táctica
        techniques = self.mapper.get_unique_techniques()
        for tech in techniques:
            tech_clean = f"{tech['id']}"
            tactic_clean = self._clean_name(tech['tactic'])
            
            content += f'''
    <owl:NamedIndividual rdf:about="#{tech_clean}">
        <pertenece_a_tactica rdf:resource="#{tactic_clean}"/>
    </owl:NamedIndividual>
'''
        
        # Relaciones ataque → técnica
        for label, techniques_list in self.mapper.lookup.items():
            # SALTAR "Normal" 
            if label == "Normal" or len(techniques_list) == 0:
                continue
                
            attack_clean = f"{self._clean_name(label)}"
            for tech in techniques_list:
                tech_clean = f"{tech['idTecnica']}"
                content += f'''
    <owl:NamedIndividual rdf:about="#{attack_clean}">
        <implementa_tecnica rdf:resource="#{tech_clean}"/>
    </owl:NamedIndividual>
'''
        
        # Relaciones técnica → mitigación
        if self.mitigations_data:
            for technique_id, technique_data in self.mitigations_data.items():
                tech_clean = f"{technique_id}"
                
                for mitigation in technique_data['mitigations']:
                    mit_clean = f"{mitigation['id']}"
                    content += f'''
    <owl:NamedIndividual rdf:about="#{tech_clean}">
        <mitigada_por rdf:resource="#{mit_clean}"/>
    </owl:NamedIndividual>
'''
        
        return content
    
    def _clean_name(self, name: str) -> str:
        """Limpia nombres para IDs válidos - SIN espacios, SIN paréntesis, SIN acentos."""
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
    
    def create_ontology_file(self):
        """Crea el archivo de ontología completo."""
        print("🔄 Generando ontología con nomenclatura limpia...")
        
        # Generar ontología completa
        complete_owl = self.generate_complete_ontology()
        ontology_path = self.output_dir / "ids_iiot_ontologia.owl"
        
        with open(ontology_path, 'w', encoding='utf-8') as f:
            f.write(complete_owl)
        
        # Generar estadísticas actualizadas
        stats = self.mapper.export_ontology_structure()
        mitigation_stats = self._get_mitigation_stats()
        
        print(f"✅ Ontología creada: {ontology_path}")
        print(f"\n📊 Estadísticas:")
        print(f"  - Técnicas: {stats['metadata']['total_techniques']}")
        print(f"  - Tácticas: {stats['metadata']['total_tactics']}")
        print(f"  - Ataques: {stats['metadata']['total_labels'] - 1}")  # -1 por "Normal"
        print(f"  - Mitigaciones únicas: {mitigation_stats['unique_mitigations']}")
        print(f"  - Relaciones técnica-mitigación: {mitigation_stats['total_relationships']}")
        
        print(f"\n🎯 ESTRUCTURA ONTOLÓGICA LIMPIA:")
        print(f"  - ✅ Ataque")
        print(f"  - ✅ Tecnica (sin espacios)") 
        print(f"  - ✅ Tactica (sin espacios)")
        print(f"  - ✅ Mitigacion (sin acentos)")
        print(f"  - ✅ AmenazaDetectada")
        
        print(f"\n🔗 PROPIEDADES SIN ESPACIOS:")
        print(f"  - esAtaque: AmenazaDetectada → Ataque")
        print(f"  - utilizaTecnica: AmenazaDetectada → Tecnica")
        print(f"  - utilizaTactica: AmenazaDetectada → Tactica") 
        print(f"  - mitigacion_recomendada: AmenazaDetectada → Mitigacion")
        print(f"  - implementa_tecnica: Ataque → Tecnica")
        print(f"  - pertenece_a_tactica: Tecnica → Tactica")
        print(f"  - mitigada_por: Tecnica → Mitigacion")
        
        return ontology_path
    
    def _get_mitigation_stats(self) -> Dict[str, int]:
        """Obtiene estadísticas de mitigaciones."""
        if not self.mitigations_data:
            return {"unique_mitigations": 0, "total_relationships": 0}
        
        unique_mitigations = set()
        total_relationships = 0
        
        for technique_id, technique_data in self.mitigations_data.items():
            for mitigation in technique_data['mitigations']:
                unique_mitigations.add(mitigation['id'])
                total_relationships += 1
        
        return {
            "unique_mitigations": len(unique_mitigations),
            "total_relationships": total_relationships
        }


def demo_ontology_populator():
    """Demo del generador de ontología con nomenclatura limpia."""
    try:
        print("🚀 Generando ontología IDS-IIoT con nomenclatura limpia...")
        populator = OntologyPopulator("../mapping/mapping_dict.json")
        
        # Generar archivo único
        ontology_file = populator.create_ontology_file()
        
        print(f"\n✅ ¡Ontología con nomenclatura limpia lista!")
        print(f"📁 Archivo: {ontology_file}")
        print(f"🔧 Sin espacios, sin paréntesis, sin acentos")
        print(f"🎯 Compatible con todas las herramientas ontológicas")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    demo_ontology_populator()