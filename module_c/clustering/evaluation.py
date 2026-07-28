"""
Evaluation Module
Computes clustering evaluation metrics including silhouette score, cluster purity, and qualitative analysis.
"""

import numpy as np
import pandas as pd
from sklearn.metrics import silhouette_score
from typing import List, Dict, Any, Tuple
from collections import Counter


class ClusterEvaluator:
    """
    Evaluates clustering results using multiple metrics.
    """
    
    def __init__(self):
        self.silhouette_score = None
        self.purity_score = None
        self.cluster_purity_details = None
    
    def compute_silhouette_score(self, distance_matrix: np.ndarray, 
                                cluster_labels: np.ndarray) -> float:
        """
        Compute silhouette score for clustering.
        
        Args:
            distance_matrix: N x N distance matrix
            cluster_labels: Cluster assignment for each sample
        
        Returns:
            Silhouette score (higher is better, range [-1, 1])
        """
        # Only compute if we have at least 2 clusters
        unique_labels = set(cluster_labels)
        n_clusters = len(unique_labels) - (1 if -1 in unique_labels else 0)
        
        if n_clusters < 2:
            print("Warning: Cannot compute silhouette score with fewer than 2 clusters")
            self.silhouette_score = 0.0
            return 0.0
        
        try:
            # Exclude noise points (-1) from silhouette calculation
            mask = cluster_labels != -1
            if np.sum(mask) < 2:
                print("Warning: Not enough non-noise points for silhouette score")
                self.silhouette_score = 0.0
                return 0.0
            
            # Since distance_matrix is N x N, we need to slice both rows and columns for the mask
            sub_distance_matrix = distance_matrix[mask][:, mask]
            score = silhouette_score(sub_distance_matrix, cluster_labels[mask], metric="precomputed")
            self.silhouette_score = score
            return score
        except Exception as e:
            print(f"Warning: Could not compute silhouette score: {e}")
            self.silhouette_score = 0.0
            return 0.0
    
    def compute_purity(self, cluster_labels: np.ndarray, 
                      true_labels: List[str]) -> float:
        """
        Compute cluster purity by comparing predicted clusters with ground truth labels.
        
        Purity = (sum of correctly clustered samples) / (total samples)
        
        Args:
            cluster_labels: Predicted cluster assignments
            true_labels: Ground truth campaign labels
        
        Returns:
            Purity score (range [0, 1])
        """
        if len(cluster_labels) != len(true_labels):
            raise ValueError("Cluster labels and true labels must have same length")
        
        # Map cluster IDs to their dominant true label
        cluster_to_label = {}
        purity_details = {}
        
        unique_clusters = set(cluster_labels)
        total_correct = 0
        total_samples = len(cluster_labels)
        
        for cluster_id in unique_clusters:
            if cluster_id == -1:
                # Skip noise points for purity calculation
                continue
            
            # Get true labels for samples in this cluster
            cluster_indices = np.where(cluster_labels == cluster_id)[0]
            cluster_true_labels = [true_labels[i] for i in cluster_indices]
            
            # Find most common true label in this cluster
            label_counter = Counter(cluster_true_labels)
            dominant_label = label_counter.most_common(1)[0][0]
            dominant_count = label_counter.most_common(1)[0][1]
            
            cluster_to_label[cluster_id] = dominant_label
            purity_details[int(cluster_id)] = {
                "dominant_label": dominant_label,
                "dominant_count": dominant_count,
                "cluster_size": len(cluster_indices),
                "label_distribution": dict(label_counter)
            }
            
            total_correct += dominant_count
        
        purity = total_correct / total_samples if total_samples > 0 else 0.0
        self.purity_score = purity
        self.cluster_purity_details = purity_details
        
        return purity
    
    def generate_evaluation_report(self, distance_matrix: np.ndarray,
                                   cluster_labels: np.ndarray,
                                   true_labels: List[str] = None,
                                   records: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate comprehensive evaluation report.
        
        Args:
            distance_matrix: N x N distance matrix
            cluster_labels: Predicted cluster assignments
            true_labels: Ground truth labels (optional, for purity calculation)
            records: Original scan records (optional, for qualitative analysis)
        
        Returns:
            Dictionary with all evaluation metrics
        """
        report = {}
        
        # Basic cluster statistics
        unique_labels = set(cluster_labels)
        n_clusters = len(unique_labels) - (1 if -1 in unique_labels else 0)
        n_noise = list(cluster_labels).count(-1)
        
        report["n_clusters"] = n_clusters
        report["n_noise"] = n_noise
        report["n_total"] = len(cluster_labels)
        report["noise_ratio"] = n_noise / len(cluster_labels) if len(cluster_labels) > 0 else 0
        
        # Silhouette score
        report["silhouette_score"] = self.compute_silhouette_score(distance_matrix, cluster_labels)
        
        # Purity score (if ground truth provided)
        if true_labels is not None:
            report["purity_score"] = self.compute_purity(cluster_labels, true_labels)
            report["cluster_purity_details"] = self.cluster_purity_details
        else:
            report["purity_score"] = None
            report["cluster_purity_details"] = None
        
        # Cluster size distribution
        cluster_sizes = {}
        for label in unique_labels:
            if label != -1:
                cluster_sizes[int(label)] = int(list(cluster_labels).count(label))
        report["cluster_sizes"] = cluster_sizes
        
        # Qualitative analysis placeholder
        if records is not None:
            report["qualitative_analysis"] = self.perform_qualitative_analysis(records, cluster_labels)
        else:
            report["qualitative_analysis"] = None
        
        return report
    
    def perform_qualitative_analysis(self, records: List[Dict[str, Any]], 
                                    cluster_labels: np.ndarray) -> Dict[str, Any]:
        """
        Perform qualitative analysis of clusters by examining sample records.
        
        Args:
            records: Scan records with fingerprints and labels
            cluster_labels: Cluster assignments
        
        Returns:
            Dictionary with qualitative analysis results
        """
        unique_clusters = set(cluster_labels)
        analysis = {}
        
        # Analyze up to 3 clusters
        clusters_to_analyze = [c for c in unique_clusters if c != -1][:3]
        
        for cluster_id in clusters_to_analyze:
            cluster_indices = np.where(cluster_labels == cluster_id)[0]
            cluster_records = [records[i] for i in cluster_indices]
            
            # Sample up to 3 records from this cluster
            sample_records = cluster_records[:3]
            
            analysis[int(cluster_id)] = {
                "cluster_size": len(cluster_records),
                "sample_urls": [r.get("url", "unknown") for r in sample_records],
                "infrastructure_patterns": {
                    "providers": list(set([r.get("Provider", "Unknown") for r in cluster_records])),
                    "ssls": list(set([r.get("SSL", "Unknown") for r in cluster_records])),
                    "nameservers": list(set([r.get("Nameserver", "Unknown") for r in cluster_records]))
                }
            }
        
        return analysis
    
    def print_report(self, report: Dict[str, Any]) -> None:
        """
        Print evaluation report in a readable format.
        
        Args:
            report: Evaluation report dictionary
        """
        print("="*60)
        print("CLUSTERING EVALUATION REPORT")
        print("="*60)
        
        print(f"\nBasic Statistics:")
        print(f"  Total samples: {report['n_total']}")
        print(f"  Number of clusters: {report['n_clusters']}")
        print(f"  Noise points: {report['n_noise']} ({report['noise_ratio']:.2%})")
        
        print(f"\nCluster Sizes:")
        for cluster_id, size in report['cluster_sizes'].items():
            print(f"  Cluster {cluster_id}: {size} samples")
        
        print(f"\nSilhouette Score: {report['silhouette_score']:.4f}")
        
        if report['purity_score'] is not None:
            print(f"\nPurity Score: {report['purity_score']:.4f}")
            print(f"\nCluster Purity Details:")
            for cluster_id, details in report['cluster_purity_details'].items():
                print(f"  Cluster {cluster_id}:")
                print(f"    Dominant label: {details['dominant_label']}")
                print(f"    Dominant count: {details['dominant_count']}/{details['cluster_size']}")
        
        if report['qualitative_analysis'] is not None:
            print(f"\nQualitative Analysis:")
            for cluster_id, details in report['qualitative_analysis'].items():
                print(f"  Cluster {cluster_id}:")
                print(f"    Size: {details['cluster_size']}")
                print(f"    Sample URLs: {', '.join(details['sample_urls'])}")
                print(f"    Providers: {', '.join(details['infrastructure_patterns']['providers'])}")
                print(f"    SSLs: {', '.join(details['infrastructure_patterns']['ssls'])}")
        
        print("="*60)


def evaluate_clustering(distance_matrix: np.ndarray,
                       cluster_labels: np.ndarray,
                       true_labels: List[str] = None,
                       records: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to evaluate clustering.
    
    Args:
        distance_matrix: N x N distance matrix
        cluster_labels: Predicted cluster assignments
        true_labels: Ground truth labels (optional)
        records: Original scan records (optional)
    
    Returns:
        Evaluation report dictionary
    """
    evaluator = ClusterEvaluator()
    report = evaluator.generate_evaluation_report(distance_matrix, cluster_labels, true_labels, records)
    return report


if __name__ == "__main__":
    # Test with sample data
    np.random.seed(42)
    
    # Create sample N x N distance matrix
    distance_matrix = np.random.uniform(0, 1, (20, 20))
    distance_matrix = (distance_matrix + distance_matrix.T) / 2
    np.fill_diagonal(distance_matrix, 0)
    
    # Create sample cluster labels
    cluster_labels = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, -1, -1, -1, -1, -1])
    
    # Create sample true labels
    true_labels = ["Campaign A"] * 5 + ["Campaign B"] * 5 + ["Campaign C"] * 5 + ["Noise"] * 5
    
    # Create sample records
    records = [
        {"url": f"site{i}.com", "Provider": "Cloudflare", "SSL": "Let's Encrypt", "Nameserver": "ns1.cloudflare.com"}
        for i in range(20)
    ]
    
    print("Testing Cluster Evaluation:")
    report = evaluate_clustering(distance_matrix, cluster_labels, true_labels, records)
    
    evaluator = ClusterEvaluator()
    evaluator.print_report(report)
