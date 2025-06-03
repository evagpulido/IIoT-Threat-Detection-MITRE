from rdflib import Graph, Namespace, URIRef, Literal, BNode
from rdflib.namespace import RDF, RDFS, XSD
from datetime import datetime
from typing import Dict, List, Any
import uuid


class AmenazaCreator:
    """
    Crea individuos reales de AmenazaDetectada en la ontología.
    Conecta detecciones ML con técnicas, tácticas y mitigaciones.
    """
    
    def __init__(self, ontology_path: str = "../ontology/ids_iiot_ontologia.owl"):
        """
        Inicializa el creador de amenazas.
        
        Args:
            ontology_path: Ruta a la ontología base
        """
        self.ontology_path = ontology_path
        self.graph = Graph()
        self.namespace = Namespace("http://universidad.es/tfm/ids-iiot/ontologia#")
        
        # Cargar ontología existente
        self._load_ontology()
        
        # Preparar namespaces
        self.graph.bind("ids", self.namespace)
        self.graph.bind("rdfs", RDFS)
        self.graph.bind("xsd", XSD)
    
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
        
    def _load_ontology(self):
        """Carga la ontología base."""
        try:
            self.graph.parse(self.ontology_path, format="xml")
            print(f"✅ Ontología base cargada: {len(self.graph)} triples")
        except Exception as e:
            print(f"❌ Error cargando ontología: {e}")
            raise
    
    def create_amenaza_detectada(self, 
                                ml_prediction: Dict[str, Any],
                                sample_index: int,
                                timestamp: datetime = None) -> str:
        """
        Crea un individuo AmenazaDetectada en la ontología.
        
        Args:
            ml_prediction: Resultado de la predicción ML
            sample_index: Índice de la muestra
            timestamp: Momento de detección
            
        Returns:
            URI del individuo creado
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # Formatear timestamp correctamente para XSD dateTime
        formatted_timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Generar ID único para la amenaza
        amenaza_id = f"AmenazaDetectada_{sample_index}"
        amenaza_uri = self.namespace[amenaza_id]
        
        # Extraer información de la predicción
        attack_label = ml_prediction['final_label']
        confidence = ml_prediction['final_confidence']
        
        if attack_label == "Normal":
            print(f"⚪ Muestra {sample_index}: Comportamiento normal - No se crea amenaza")
            return None
        
        # 1. Crear el individuo AmenazaDetectada
        self.graph.add((amenaza_uri, RDF.type, self.namespace.AmenazaDetectada))
        self.graph.add((amenaza_uri, RDFS.label, Literal(f"Amenaza_{sample_index}")))
        
        # 2. Propiedades básicas de la amenaza
        self.graph.add((amenaza_uri, self.namespace.tieneConfianza, Literal(confidence, datatype=XSD.decimal)))
        self.graph.add((amenaza_uri, self.namespace.detectadaEn, Literal(formatted_timestamp)))
        self.graph.add((amenaza_uri, self.namespace.indiceMuestra, Literal(sample_index, datatype=XSD.integer)))
        
        # 3. Conectar con tipo de ataque
        attack_uri = self._connect_to_attack_type(amenaza_uri, attack_label)
        
        # 4. Conectar con técnicas MITRE (y automáticamente con tácticas y mitigaciones)
        techniques = self._get_techniques_for_attack(attack_label)
        for technique in techniques:
            self._connect_to_technique(amenaza_uri, technique)
        
        print(f"✅ Creada {amenaza_id}: {attack_label} (conf: {confidence:.3f})")
        return amenaza_uri
    
    def _connect_to_attack_type(self, amenaza_uri: URIRef, attack_label: str) -> URIRef:
        """Conecta amenaza con tipo de ataque."""
        attack_clean = self._clean_name(attack_label)
        attack_uri = self.namespace[attack_clean]
        self.graph.add((amenaza_uri, self.namespace.esAtaque, attack_uri))
        return attack_uri
    
    def _get_techniques_for_attack(self, attack_label: str) -> List[Dict]:
        """
        Obtiene técnicas MITRE para una etiqueta de ataque.
        Consulta el mapping existente en la ontología.
        """
        # Buscar en el grafo las técnicas asociadas a esta etiqueta
        techniques = []
        attack_clean = self._clean_name(attack_label)
        
        # Consulta SPARQL para encontrar técnicas via Ataque
        query = f"""
        PREFIX ids: <{self.namespace}>
        SELECT ?tecnica ?tecID ?tecNombre ?tactica
        WHERE {{
            ids:{attack_clean} ids:implementa_tecnica ?tecnica .
            ?tecnica ids:tieneID ?tecID .
            ?tecnica ids:tieneNombre ?tecNombre .
            ?tecnica ids:pertenece_a_tactica ?tacticaURI .
            ?tacticaURI ids:tieneNombre ?tactica .
        }}
        """
        
        results = self.graph.query(query)
        for row in results:
            techniques.append({
                'uri': row.tecnica,
                'id': str(row.tecID),
                'name': str(row.tecNombre),
                'tactic': str(row.tactica)
            })
        
        return techniques
    
    def _connect_to_technique(self, amenaza_uri: URIRef, technique: Dict):
        """Conecta amenaza con técnica y táctica específica."""
        technique_uri = technique['uri']
        
        # Conectar con técnica
        self.graph.add((amenaza_uri, self.namespace.utilizaTecnica, technique_uri))
        
        # Obtener táctica de la técnica
        tactic_query = f"""
        PREFIX ids: <{self.namespace}>
        SELECT ?tactica
        WHERE {{
            <{technique_uri}> ids:pertenece_a_tactica ?tactica .
        }}
        """
        
        tactic_results = self.graph.query(tactic_query)
        for tactic_row in tactic_results:
            tactic_uri = tactic_row.tactica
            self.graph.add((amenaza_uri, self.namespace.utilizaTactica, tactic_uri))
        
        # Obtener mitigaciones para la técnica
        self._connect_to_mitigations(amenaza_uri, technique_uri)
    
    def _connect_to_mitigations(self, amenaza_uri: URIRef, technique_uri: URIRef):
        """Conecta amenaza con mitigaciones recomendadas."""
        # Buscar mitigaciones para esta técnica
        mitigation_query = f"""
        PREFIX ids: <{self.namespace}>
        SELECT ?mitigacion
        WHERE {{
            <{technique_uri}> ids:mitigada_por ?mitigacion .
        }}
        """
        
        mitigation_results = self.graph.query(mitigation_query)
        for mit_row in mitigation_results:
            mitigation_uri = mit_row.mitigacion
            self.graph.add((amenaza_uri, self.namespace.mitigacion_recomendada, mitigation_uri))
    
    def save_updated_ontology(self, output_path: str = None):
        """Guarda la ontología actualizada con las nuevas amenazas."""
        if output_path is None:
            output_path = self.ontology_path.replace('.owl', '_with_amenazas.owl')
        
        self.graph.serialize(destination=output_path, format="xml")
        print(f"💾 Ontología actualizada guardada en: {output_path}")
        return output_path
    
    def get_amenazas_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas de las amenazas creadas."""
        query = f"""
        PREFIX ids: <{self.namespace}>
        SELECT 
            (COUNT(?amenaza) as ?total_amenazas)
            (COUNT(DISTINCT ?tecnica) as ?tecnicas_utilizadas)
            (COUNT(DISTINCT ?tactica) as ?tacticas_utilizadas)
            (COUNT(DISTINCT ?mitigacion) as ?mitigaciones_recomendadas)
        WHERE {{
            ?amenaza a ids:AmenazaDetectada .
            OPTIONAL {{ ?amenaza ids:utilizaTecnica ?tecnica }}
            OPTIONAL {{ ?amenaza ids:utilizaTactica ?tactica }}
            OPTIONAL {{ ?amenaza ids:mitigacion_recomendada ?mitigacion }}
        }}
        """
        
        results = list(self.graph.query(query))
        if results:
            row = results[0]
            return {
                'total_amenazas': int(row[0]),
                'tecnicas_utilizadas': int(row[1]),
                'tacticas_utilizadas': int(row[2]),
                'mitigaciones_recomendadas': int(row[3]),
                'total_triples': len(self.graph)
            }
        
        return {'error': 'No se pudieron obtener estadísticas'}


def demo_amenaza_creator():
    """
    Demo del creador de amenazas con nomenclatura limpia.
    """
    print("🚀 Probando Creador de Amenazas con nomenclatura limpia...")
    
    try:
        creator = AmenazaCreator()
        
        # Demo 1: Crear amenaza de SQL Injection
        print("\n=== Demo 1: Crear Amenaza SQL Injection ===")
        ml_prediction = {
            'final_label': 'sql_injection',
            'final_confidence': 0.94
        }
        
        amenaza_uri = creator.create_amenaza_detectada(ml_prediction, sample_index=0)
        
        if amenaza_uri:
            print(f"Amenaza creada: {amenaza_uri}")
        
        # Demo 2: Crear amenaza de DDoS
        print("\n=== Demo 2: Crear Amenaza DDoS ===")
        ml_prediction2 = {
            'final_label': 'ddos_tcp_syn',
            'final_confidence': 0.87
        }
        
        amenaza_uri2 = creator.create_amenaza_detectada(ml_prediction2, sample_index=1)
        
        # Demo 3: Comportamiento normal (no debe crear amenaza)
        print("\n=== Demo 3: Comportamiento Normal ===")
        ml_prediction3 = {
            'final_label': 'Normal',
            'final_confidence': 0.92
        }
        
        amenaza_uri3 = creator.create_amenaza_detectada(ml_prediction3, sample_index=2)
        
        # Demo 4: Guardar ontología actualizada
        print("\n=== Demo 4: Guardar Ontología ===")
        output_path = creator.save_updated_ontology()
        print(f"💾 Nueva ontología con amenazas: {output_path}")
        
        print("\n✅ Creador de Amenazas funcionando correctamente!")
        print("🎯 Nomenclatura limpia: sin espacios, sin paréntesis, sin acentos")
        print("🔗 Propiedades actualizadas:")
        print("  - esAtaque, utilizaTecnica, utilizaTactica")
        print("  - mitigacion_recomendada, implementa_tecnica")
        print("  - pertenece_a_tactica, mitigada_por")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    demo_amenaza_creator()