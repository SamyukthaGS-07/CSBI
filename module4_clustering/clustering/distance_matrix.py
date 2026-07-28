"""
Distance Matrix Generator
Computes a pairwise distance matrix between scan records using categorical fields
and HTML similarity, suitable for DBSCAN with metric="precomputed".
"""

import numpy as np
from typing import List, Dict, Any, Tuple

class DistanceMatrixGenerator:
    """
    Generates an NxN distance matrix from fingerprints and HTML similarity matrix.
    """
    
    def __init__(self, weights: Dict[str, float] = None):
        """
        Initialize with optional custom weights for each feature.
        """
        # Default weights for distance calculation
        self.weights = weights or {
            "asn": 1.0,
            "provider": 1.0,
            "nameserver": 1.0,
            "ssl": 1.0,
            "ip_block": 1.0,
            "html_sim": 2.0  # Give higher weight to HTML similarity
        }
        self.fitted = False

    def compute_distance_matrix(self, fingerprints: List[Dict[str, Any]], similarity_matrix: np.ndarray) -> np.ndarray:
        """
        Compute the NxN distance matrix.
        
        Args:
            fingerprints: List of fingerprint dictionaries
            similarity_matrix: NxN similarity matrix from HTML comparison
        
        Returns:
            NxN distance matrix
        """
        n = len(fingerprints)
        dist_matrix = np.zeros((n, n), dtype=float)
        
        if n == 0:
            return dist_matrix
            
        for i in range(n):
            for j in range(i + 1, n):
                fp_i = fingerprints[i]
                fp_j = fingerprints[j]
                
                dist = 0.0
                
                # Categorical differences (distance = 1 if different, 0 if same)
                if str(fp_i.get("ASN")) != str(fp_j.get("ASN")):
                    dist += self.weights["asn"]
                    
                if str(fp_i.get("Provider")) != str(fp_j.get("Provider")):
                    dist += self.weights["provider"]
                    
                if str(fp_i.get("Nameserver")) != str(fp_j.get("Nameserver")):
                    dist += self.weights["nameserver"]
                    
                if str(fp_i.get("SSL")) != str(fp_j.get("SSL")):
                    dist += self.weights["ssl"]
                    
                if str(fp_i.get("IPBlock")) != str(fp_j.get("IPBlock")):
                    dist += self.weights["ip_block"]
                
                # HTML Distance (1 - similarity)
                # Ensure we don't go out of bounds if similarity_matrix is smaller
                if i < len(similarity_matrix) and j < len(similarity_matrix):
                    html_dist = max(0.0, 1.0 - similarity_matrix[i, j])
                    dist += self.weights["html_sim"] * html_dist
                else:
                    # Max distance if no similarity data available
                    dist += self.weights["html_sim"] * 1.0
                
                dist_matrix[i, j] = dist
                dist_matrix[j, i] = dist  # Symmetric
                
        self.fitted = True
        return dist_matrix

def create_distance_matrix(fingerprints: List[Dict[str, Any]], 
                           similarity_matrix: np.ndarray) -> Tuple[np.ndarray, DistanceMatrixGenerator]:
    """
    Convenience function to create the distance matrix.
    
    Args:
        fingerprints: List of fingerprint dictionaries
        similarity_matrix: NxN similarity matrix from HTML comparison
    
    Returns:
        Tuple of (distance matrix, generator instance)
    """
    generator = DistanceMatrixGenerator()
    dist_matrix = generator.compute_distance_matrix(fingerprints, similarity_matrix)
    return dist_matrix, generator


if __name__ == "__main__":
    # Test with sample data
    sample_fingerprints = [
        {"ASN": 24560, "Provider": "Cloudflare", "Nameserver": "ns1.cloudflare.com", "SSL": "Let's Encrypt", "IPBlock": "1.1.1.0/24"},
        {"ASN": 24560, "Provider": "Cloudflare", "Nameserver": "ns2.cloudflare.com", "SSL": "Let's Encrypt", "IPBlock": "1.1.1.0/24"},
        {"ASN": 13335, "Provider": "Cloudflare", "Nameserver": "ns1.cloudflare.com", "SSL": "Cloudflare", "IPBlock": "2.2.2.0/24"},
        {"ASN": 15169, "Provider": "Google", "Nameserver": "ns1.google.com", "SSL": "Google Trust Services", "IPBlock": "8.8.8.0/24"},
    ]
    
    # Sample similarity matrix
    sample_similarity = np.array([
        [1.0, 0.9, 0.7, 0.3],
        [0.9, 1.0, 0.7, 0.3],
        [0.7, 0.7, 1.0, 0.4],
        [0.3, 0.3, 0.4, 1.0],
    ])
    
    dist_matrix, generator = create_distance_matrix(sample_fingerprints, sample_similarity)
    
    print("Distance Matrix:")
    np.set_printoptions(precision=2)
    print(dist_matrix)
    print(f"\nShape: {dist_matrix.shape}")
