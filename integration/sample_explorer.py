import pickle
import pandas as pd
import numpy as np
from typing import List, Dict, Any
from tabulate import tabulate


class SampleExplorer:
    """
    Explorador de muestras del dataset para análisis detallado.
    Muestra características completas en formato tabla.
    """
    
    def __init__(self, train_test_data_path: str = "../../IDS/data/train_test_data.pkl"):
        """
        Inicializa el explorador de muestras.
        
        Args:
            train_test_data_path: Ruta a los datos de entrenamiento/test
        """
        print("🔄 Cargando datos del dataset...")
        self.data = self._load_data(train_test_data_path)
        
        if self.data:
            print("✅ Datos cargados correctamente")
            self._show_dataset_info()
        else:
            print("❌ Error cargando datos")
    
    def _load_data(self, data_path: str) -> Dict:
        """Carga los datos de test desde pickle."""
        try:
            with open(data_path, 'rb') as f:
                data = pickle.load(f)
            return data
        except Exception as e:
            print(f"❌ Error cargando datos: {e}")
            return {}
    
    def _show_dataset_info(self):
        """Muestra información general del dataset."""
        print(f"\n📊 Información del Dataset:")
        print(f"  - X_test shape: {self.data['X_test_original'].shape}")
        print(f"  - Features: {list(self.data['X_test_original'].columns)}")
        print(f"  - Clases binarias únicas: {sorted(self.data['y_test_bin'].unique())}")
        print(f"  - Clases multiclase únicas: {sorted(self.data['y_test_multi'].unique())}")
    
    def explore_samples(self, sample_indices: List[int]) -> None:
        """
        Explora muestras específicas mostrando todas sus características.
        
        Args:
            sample_indices: Lista de índices de muestras a explorar
        """
        if not self.data:
            print("❌ No hay datos cargados")
            return
        
        X_test = self.data['X_test_original']
        y_test_bin = self.data['y_test_bin']
        y_test_multi = self.data['y_test_multi']
        
        print(f"\n🔍 Explorando {len(sample_indices)} muestras del dataset...")
        print("=" * 100)
        
        for i, sample_idx in enumerate(sample_indices):
            if sample_idx >= len(X_test):
                print(f"❌ Índice {sample_idx} fuera de rango (max: {len(X_test)-1})")
                continue
            
            print(f"\n📊 MUESTRA {i+1}/{len(sample_indices)} - Índice: {sample_idx}")
            print("-" * 80)
            
            # Obtener datos de la muestra
            sample_data = X_test.iloc[sample_idx]
            ground_truth_bin = y_test_bin.iloc[sample_idx]
            ground_truth_multi = y_test_multi.iloc[sample_idx]
            
            # Información de etiquetas
            print(f"🏷️  ETIQUETAS:")
            print(f"   - Binaria (0=Normal, 1=Ataque): {ground_truth_bin}")
            print(f"   - Multiclase: {ground_truth_multi}")
            
            # Tabla de características
            self._show_sample_table(sample_data, sample_idx)
            
            print("=" * 100)
    
    def _show_sample_table(self, sample_data: pd.Series, sample_idx: int) -> None:
        """
        Muestra las características de una muestra en formato tabla.
        
        Args:
            sample_data: Serie con las características de la muestra
            sample_idx: Índice de la muestra
        """
        print(f"\n📋 CARACTERÍSTICAS (17 features):")
        
        # Crear tabla con todas las características
        table_data = []
        for i, (feature_name, value) in enumerate(sample_data.items()):
            # Formatear valor según tipo
            if isinstance(value, float):
                formatted_value = f"{value:.6f}" if abs(value) < 1 else f"{value:.3f}"
            else:
                formatted_value = str(value)
            
            table_data.append([
                i+1,
                feature_name,
                formatted_value,
                type(value).__name__
            ])
        
        # Mostrar tabla
        headers = ["#", "Feature", "Valor", "Tipo"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    def explore_by_attack_type(self, attack_type: str, num_samples: int = 3) -> None:
        """
        Explora muestras de un tipo específico de ataque.
        
        Args:
            attack_type: Tipo de ataque a explorar
            num_samples: Número de muestras a mostrar
        """
        if not self.data:
            print("❌ No hay datos cargados")
            return
        
        y_test_multi = self.data['y_test_multi']
        
        # Encontrar índices del tipo de ataque
        attack_indices = y_test_multi[y_test_multi == attack_type].index.tolist()
        
        if not attack_indices:
            print(f"❌ No se encontraron muestras del tipo: {attack_type}")
            print(f"Tipos disponibles: {sorted(y_test_multi.unique())}")
            return
        
        # Tomar las primeras num_samples
        selected_indices = attack_indices[:num_samples]
        
        print(f"\n🎯 Explorando {len(selected_indices)} muestras del tipo: {attack_type}")
        print(f"📊 Total disponibles: {len(attack_indices)} muestras")
        
        self.explore_samples(selected_indices)
    
    def compare_samples(self, sample_indices: List[int]) -> None:
        """
        Compara múltiples muestras lado a lado.
        
        Args:
            sample_indices: Lista de índices a comparar
        """
        if not self.data:
            print("❌ No hay datos cargados")
            return
        
        X_test = self.data['X_test_original']
        y_test_bin = self.data['y_test_bin']
        y_test_multi = self.data['y_test_multi']
        
        print(f"\n🔄 Comparando {len(sample_indices)} muestras...")
        
        # Validar índices
        valid_indices = [idx for idx in sample_indices if idx < len(X_test)]
        if len(valid_indices) != len(sample_indices):
            print(f"⚠️ Algunos índices están fuera de rango. Usando: {valid_indices}")
        
        # Crear tabla comparativa
        table_data = []
        
        # Header con índices
        headers = ["Feature"] + [f"Muestra {idx}" for idx in valid_indices]
        
        # Agregar fila de etiquetas
        labels_row = ["ETIQUETA"]
        for idx in valid_indices:
            label = y_test_multi.iloc[idx]
            labels_row.append(label)
        table_data.append(labels_row)
        
        # Agregar filas de características
        feature_names = X_test.columns
        for feature in feature_names:
            row = [feature]
            for idx in valid_indices:
                value = X_test.iloc[idx][feature]
                if isinstance(value, float):
                    formatted_value = f"{value:.3f}"
                else:
                    formatted_value = str(value)
                row.append(formatted_value)
            table_data.append(row)
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    def get_attack_distribution(self) -> None:
        """Muestra la distribución de tipos de ataque en el dataset."""
        if not self.data:
            print("❌ No hay datos cargados")
            return
        
        y_test_multi = self.data['y_test_multi']
        distribution = y_test_multi.value_counts().sort_values(ascending=False)
        
        print(f"\n📊 Distribución de Ataques en el Dataset:")
        print("-" * 50)
        
        table_data = []
        for attack_type, count in distribution.items():
            percentage = (count / len(y_test_multi)) * 100
            table_data.append([attack_type, count, f"{percentage:.2f}%"])
        
        headers = ["Tipo de Ataque", "Cantidad", "Porcentaje"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))


def demo_sample_explorer():
    """
    Demo del explorador de muestras.
    """
    print("🚀 Demo del Explorador de Muestras...")
    
    try:
        # Inicializar explorador
        explorer = SampleExplorer()
        
        # Demo 1: Explorar muestras específicas
        print("\n" + "="*100)
        print("📊 DEMO 1: Explorando muestras específicas")
        sample_indices = [6442, 4052, 525, 5955, 2948]
        explorer.explore_samples(sample_indices)
        
        # Demo 2: Distribución de ataques
        print("\n" + "="*100)
        print("📊 DEMO 2: Distribución de ataques")
        explorer.get_attack_distribution()
        
        # Demo 3: Explorar por tipo de ataque
        print("\n" + "="*100)
        print("📊 DEMO 3: Explorando muestras de DDoS")
        explorer.explore_by_attack_type("ddos_tcp_syn", num_samples=2)
        
        # Demo 4: Comparación lado a lado
        print("\n" + "="*100)
        print("📊 DEMO 4: Comparación de 3 muestras")
        explorer.compare_samples([100, 200, 300])
        
        print("\n✅ Demo completado!")
        
    except Exception as e:
        print(f"❌ Error en demo: {e}")


def explore_specific_samples():
    """
    Función para explorar las muestras específicas que mencionaste.
    """
    print("🎯 Explorando muestras específicas del pipeline...")
    
    explorer = SampleExplorer()
    
    # Tus índices específicos
    target_indices = [6276, 5984, 4118]
    
    print(f"\n🔍 Analizando muestras: {target_indices}")
    explorer.explore_samples(target_indices)
    
    # Bonus: Comparación lado a lado
    print(f"\n🔄 Comparación lado a lado:")
    explorer.compare_samples(target_indices)


if __name__ == "__main__":
    # Ejecutar demo completo
    #demo_sample_explorer()
    
    # O ejecutar solo las muestras específicas
    explore_specific_samples()