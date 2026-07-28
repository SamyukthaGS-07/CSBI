"""
DBSCAN Clustering Module
Performs density-based clustering on feature vectors to identify scam campaigns.
"""

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.metrics import silhouette_score
from typing import Tuple, Dict, Any, List


class DBSCAMClusterer:
    """
    DBSCAN clustering with parameter tuning support.
    """
    
    def __init__(self, eps: float = 0.5, min_samples: int = 3):
        """
        Initialize DBSCAN clusterer.
        
        Args:
            eps: Maximum distance between two samples for one to be considered as in the neighborhood of the other
            min_samples: Number of samples in a neighborhood for a point to be considered as a core point
        """
        self.eps = eps
        self.min_samples = min_samples
        self.dbscan = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed")
        self.labels = None
        self.best_eps = eps
        self.best_min_samples = min_samples
    
    def fit(self, distance_matrix: np.ndarray) -> np.ndarray:
        """
        Fit DBSCAN on distance matrix.
        
        Args:
            distance_matrix: N x N distance matrix
        
        Returns:
            Cluster labels (-1 for noise points)
        """
        self.dbscan = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric="precomputed")
        self.labels = self.dbscan.fit_predict(distance_matrix)
        return self.labels
    
    def tune_parameters(self, distance_matrix: np.ndarray, 
                       eps_range: List[float] = None,
                       min_samples_range: List[int] = None) -> Dict[str, Any]:
        """
        Tune DBSCAN parameters using silhouette score.
        
        Args:
            distance_matrix: N x N distance matrix
            eps_range: List of eps values to try (default: [0.3, 0.5, 0.7, 1.0, 1.5, 2.0])
            min_samples_range: List of min_samples values to try (default: [2, 3, 5, 10])
        
        Returns:
            Dictionary with best parameters and corresponding score
        """
        if eps_range is None:
            eps_range = [0.3, 0.5, 0.7, 1.0, 1.5, 2.0]
        if min_samples_range is None:
            min_samples_range = [2, 3, 5, 10]
        
        best_score = -1
        best_eps = self.eps
        best_min_samples = self.min_samples
        best_labels = None
        
        print("Tuning DBSCAN parameters...")
        for eps in eps_range:
            for min_samples in min_samples_range:
                dbscan = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed")
                labels = dbscan.fit_predict(distance_matrix)
                
                # Only compute silhouette score if we have at least 2 clusters and some noise
                n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
                if n_clusters >= 2:
                    try:
                        score = silhouette_score(distance_matrix, labels, metric="precomputed")
                        print(f"  eps={eps:.1f}, min_samples={min_samples}: clusters={n_clusters}, silhouette={score:.3f}")
                        
                        if score > best_score:
                            best_score = score
                            best_eps = eps
                            best_min_samples = min_samples
                            best_labels = labels
                    except Exception as e:
                        # Silhouette score can fail if all points are in one cluster
                        print(f"  eps={eps:.1f}, min_samples={min_samples}: clusters={n_clusters}, silhouette=undefined")
        
        if best_labels is not None:
            self.eps = best_eps
            self.min_samples = best_min_samples
            self.best_eps = best_eps
            self.best_min_samples = best_min_samples
            self.labels = best_labels
            print(f"\nBest parameters: eps={best_eps}, min_samples={best_min_samples}, silhouette={best_score:.3f}")
        else:
            # If no valid clustering found, use default
            self.fit(distance_matrix)
            print(f"No valid clustering found during tuning, using default parameters")
        
        return {
            "best_eps": self.best_eps,
            "best_min_samples": self.best_min_samples,
            "best_silhouette": best_score if best_score != -1 else None
        }
    
    def get_cluster_info(self) -> Dict[str, Any]:
        """
        Get information about the clustering results.
        
        Returns:
            Dictionary with cluster statistics
        """
        if self.labels is None:
            return {"error": "Model not fitted yet"}
        
        unique_labels = set(self.labels)
        n_clusters = len(unique_labels) - (1 if -1 in unique_labels else 0)
        n_noise = list(self.labels).count(-1)
        
        cluster_sizes = {}
        for label in unique_labels:
            if label != -1:
                cluster_sizes[int(label)] = int(list(self.labels).count(label))
        
        return {
            "n_clusters": n_clusters,
            "n_noise": n_noise,
            "n_total": len(self.labels),
            "cluster_sizes": cluster_sizes,
            "noise_ratio": n_noise / len(self.labels) if len(self.labels) > 0 else 0
        }


def perform_clustering(distance_matrix: np.ndarray, 
                      eps: float = 0.5, 
                      min_samples: int = 3,
                      tune: bool = False) -> Tuple[np.ndarray, Dict[str, Any]]:
    """
    Convenience function to perform DBSCAN clustering.
    
    Args:
        distance_matrix: N x N distance matrix
        eps: DBSCAN eps parameter
        min_samples: DBSCAN min_samples parameter
        tune: Whether to tune parameters automatically
    
    Returns:
        Tuple of (cluster labels, cluster info dictionary)
    """
    clusterer = DBSCAMClusterer(eps=eps, min_samples=min_samples)
    
    if tune:
        clusterer.tune_parameters(distance_matrix)
    else:
        clusterer.fit(distance_matrix)
    
    return clusterer.labels, clusterer.get_cluster_info()


if __name__ == "__main__":
    # Test with sample distance matrix
    np.random.seed(42)
    
    # Create sample N x N distance matrix
    # Points 0-4 are close to each other, 5-9 are close to each other
    distance_matrix = np.zeros((10, 10))
    for i in range(10):
        for j in range(10):
            if (i < 5 and j < 5) or (i >= 5 and j >= 5):
                distance_matrix[i, j] = np.random.uniform(0, 0.5)
            else:
                distance_matrix[i, j] = np.random.uniform(2.0, 3.0)
            
            # Make symmetric and zero diagonal
            if i == j:
                distance_matrix[i, j] = 0
            else:
                distance_matrix[j, i] = distance_matrix[i, j]
    
    print("Testing DBSCAN Clustering (precomputed):")
    print(f"Distance matrix shape: {distance_matrix.shape}")
    
    # Test without tuning
    labels, info = perform_clustering(distance_matrix, eps=1.0, min_samples=3)
    print(f"\nClustering without tuning:")
    print(f"  Labels: {labels}")
    print(f"  Info: {info}")
    
    # Test with tuning
    print("\n" + "="*50)
    labels_tuned, info_tuned = perform_clustering(distance_matrix, eps=0.5, min_samples=3, tune=True)
    print(f"\nClustering with tuning:")
    print(f"  Labels: {labels_tuned}")
    print(f"  Info: {info_tuned}")

