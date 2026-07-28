"""
Cluster Labeling Module
Generates descriptive labels for clusters based on dominant infrastructure patterns.
"""

from typing import List, Dict, Any, Tuple
from collections import Counter
import numpy as np


class ClusterLabeler:
    """
    Generates descriptive labels for scam campaign clusters.
    """
    
    def __init__(self):
        self.cluster_labels = {}
    
    def analyze_cluster_characteristics(self, cluster_id: int, 
                                       cluster_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze the characteristics of a cluster.
        
        Args:
            cluster_id: ID of the cluster
            cluster_records: List of scan records in this cluster
        
        Returns:
            Dictionary with cluster characteristics
        """
        if not cluster_records:
            return {}
        
        # Extract features
        providers = [r.get("Provider", "Unknown") for r in cluster_records]
        ssls = [r.get("SSL", "Unknown") for r in cluster_records]
        nameservers = [r.get("Nameserver", "Unknown") for r in cluster_records]
        asns = [r.get("ASN", 0) for r in cluster_records]
        
        # Get most common values
        provider_counter = Counter(providers)
        ssl_counter = Counter(ssls)
        nameserver_counter = Counter(nameservers)
        
        return {
            "cluster_id": cluster_id,
            "size": len(cluster_records),
            "dominant_provider": provider_counter.most_common(1)[0][0] if provider_counter else "Unknown",
            "dominant_ssl": ssl_counter.most_common(1)[0][0] if ssl_counter else "Unknown",
            "dominant_nameserver": nameserver_counter.most_common(1)[0][0] if nameserver_counter else "Unknown",
            "asn_range": (min(asns), max(asns)) if asns else (0, 0),
            "provider_distribution": dict(provider_counter.most_common(3)),
            "ssl_distribution": dict(ssl_counter.most_common(3))
        }
    
    def generate_label(self, cluster_characteristics: Dict[str, Any]) -> str:
        """
        Generate a descriptive label for a cluster.
        
        Args:
            cluster_characteristics: Dictionary with cluster characteristics
        
        Returns:
            Descriptive label string
        """
        provider = cluster_characteristics.get("dominant_provider", "Unknown")
        ssl = cluster_characteristics.get("dominant_ssl", "Unknown")
        
        # Generate label based on infrastructure patterns
        if provider == "Cloudflare" and ssl == "Let's Encrypt":
            return "Cloudflare/Let's Encrypt Campaign"
        elif provider == "Cloudflare" and ssl == "Cloudflare":
            return "Cloudflare Infrastructure Campaign"
        elif provider == "Google":
            return "Google Infrastructure Campaign"
        elif provider == "Amazon":
            return "AWS Infrastructure Campaign"
        elif "Unknown" in provider or provider == "Unknown":
            return "Unknown Infrastructure Campaign"
        else:
            return f"{provider} Infrastructure Campaign"
    
    def label_clusters(self, records: List[Dict[str, Any]], 
                      cluster_labels: np.ndarray) -> Dict[int, str]:
        """
        Generate labels for all clusters.
        
        Args:
            records: List of all scan records with fingerprints
            cluster_labels: Cluster assignment for each record
        
        Returns:
            Dictionary mapping cluster_id to label
        """
        unique_clusters = set(cluster_labels)
        cluster_id_to_label = {}
        
        for cluster_id in unique_clusters:
            if cluster_id == -1:
                # Noise points
                cluster_id_to_label[cluster_id] = "Legitimate/Unknown"
                continue
            
            # Get records in this cluster
            cluster_indices = np.where(cluster_labels == cluster_id)[0]
            cluster_records = [records[i] for i in cluster_indices]
            
            # Analyze characteristics
            characteristics = self.analyze_cluster_characteristics(cluster_id, cluster_records)
            
            # Generate label
            label = self.generate_label(characteristics)
            cluster_id_to_label[cluster_id] = label
        
        self.cluster_labels = cluster_id_to_label
        return cluster_id_to_label
    
    def update_records_with_labels(self, records: List[Dict[str, Any]], 
                                   cluster_labels: np.ndarray) -> List[Dict[str, Any]]:
        """
        Update scan records with cluster_id and cluster_label.
        
        Args:
            records: List of scan records
            cluster_labels: Cluster assignment for each record
        
        Returns:
            Updated records with cluster_id and cluster_label
        """
        updated_records = []
        
        for i, record in enumerate(records):
            cluster_id = int(cluster_labels[i])
            cluster_label = self.cluster_labels.get(cluster_id, "Unknown")
            
            updated_record = record.copy()
            updated_record["cluster_id"] = cluster_id
            updated_record["cluster_label"] = cluster_label
            updated_records.append(updated_record)
        
        return updated_records
    
    def get_cluster_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all clusters.
        
        Returns:
            Dictionary with cluster summary
        """
        return {
            "n_clusters": len([k for k in self.cluster_labels.keys() if k != -1]),
            "has_noise": -1 in self.cluster_labels,
            "cluster_labels": self.cluster_labels
        }


def label_clusters(records: List[Dict[str, Any]], 
                 cluster_labels: np.ndarray) -> Tuple[Dict[int, str], List[Dict[str, Any]]]:
    """
    Convenience function to label clusters and update records.
    
    Args:
        records: List of scan records with fingerprints
        cluster_labels: Cluster assignment for each record
    
    Returns:
        Tuple of (cluster_id_to_label dictionary, updated records)
    """
    labeler = ClusterLabeler()
    cluster_id_to_label = labeler.label_clusters(records, cluster_labels)
    updated_records = labeler.update_records_with_labels(records, cluster_labels)
    
    return cluster_id_to_label, updated_records


if __name__ == "__main__":
    # Test with sample data
    sample_records = [
        {"url": "site1.com", "Provider": "Cloudflare", "SSL": "Let's Encrypt", "Nameserver": "ns1.cloudflare.com", "ASN": 24560},
        {"url": "site2.com", "Provider": "Cloudflare", "SSL": "Let's Encrypt", "Nameserver": "ns2.cloudflare.com", "ASN": 24560},
        {"url": "site3.com", "Provider": "Cloudflare", "SSL": "Let's Encrypt", "Nameserver": "ns1.cloudflare.com", "ASN": 24560},
        {"url": "site4.com", "Provider": "Google", "SSL": "Google Trust Services", "Nameserver": "ns1.google.com", "ASN": 15169},
        {"url": "site5.com", "Provider": "Google", "SSL": "Google Trust Services", "Nameserver": "ns2.google.com", "ASN": 15169},
        {"url": "site6.com", "Provider": "Unknown", "SSL": "Unknown", "Nameserver": "Unknown", "ASN": 0},
    ]
    
    sample_cluster_labels = np.array([0, 0, 0, 1, 1, -1])
    
    print("Testing Cluster Labeling:")
    cluster_id_to_label, updated_records = label_clusters(sample_records, sample_cluster_labels)
    
    print("\nCluster Labels:")
    for cluster_id, label in cluster_id_to_label.items():
        print(f"  Cluster {cluster_id}: {label}")
    
    print("\nUpdated Records:")
    for record in updated_records:
        print(f"  {record['url']}: cluster_id={record['cluster_id']}, label={record['cluster_label']}")
