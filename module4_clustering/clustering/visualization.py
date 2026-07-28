"""
Visualization Module for Clustering Evaluation
Generates visualizations for DBSCAN clusters, silhouette scores, cluster purity, and sample results.
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.manifold import TSNE
from typing import List, Dict, Any
import os


class ClusterVisualizer:
    """
    Creates visualizations for clustering results and evaluation metrics.
    """
    
    def __init__(self, output_dir: str = "data/visualizations"):
        """
        Initialize visualizer.
        
        Args:
            output_dir: Directory to save visualization images
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def plot_clusters_2d(self, feature_matrix: np.ndarray, 
                        cluster_labels: np.ndarray,
                        title: str = "DBSCAN Clustering Results",
                        save_path: str = None) -> None:
        """
        Visualize clusters in 2D using t-SNE dimensionality reduction.
        
        Args:
            feature_matrix: N x D feature matrix
            cluster_labels: Cluster assignments
            title: Plot title
            save_path: Path to save the plot (optional)
        """
        # Reduce to 2D using t-SNE if needed
        if feature_matrix.shape[1] > 2:
            tsne = TSNE(n_components=2, random_state=42, perplexity=min(30, len(feature_matrix)-1))
            features_2d = tsne.fit_transform(feature_matrix)
        else:
            features_2d = feature_matrix
        
        # Plot
        plt.figure(figsize=(10, 8))
        unique_labels = set(cluster_labels)
        colors = plt.cm.tab20(np.linspace(0, 1, len(unique_labels)))
        
        for label, color in zip(unique_labels, colors):
            if label == -1:
                # Noise points in black
                mask = cluster_labels == label
                plt.scatter(features_2d[mask, 0], features_2d[mask, 1], 
                           c='black', marker='x', s=100, label='Noise', alpha=0.7)
            else:
                mask = cluster_labels == label
                plt.scatter(features_2d[mask, 0], features_2d[mask, 1], 
                           c=[color], label=f'Cluster {int(label)}', alpha=0.7, s=100)
        
        plt.title(title, fontsize=14, fontweight='bold')
        plt.xlabel('Dimension 1', fontsize=12)
        plt.ylabel('Dimension 2', fontsize=12)
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved cluster visualization to {save_path}")
        else:
            save_path = os.path.join(self.output_dir, "cluster_visualization.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved cluster visualization to {save_path}")
        
        plt.close()
    
    def plot_silhouette_scores(self, silhouette_scores: List[float],
                               parameter_values: List[float],
                               param_name: str = "eps",
                               title: str = "Silhouette Score vs Parameter",
                               save_path: str = None) -> None:
        """
        Plot silhouette scores across parameter values.
        
        Args:
            silhouette_scores: List of silhouette scores
            parameter_values: List of parameter values
            param_name: Name of the parameter
            title: Plot title
            save_path: Path to save the plot (optional)
        """
        plt.figure(figsize=(10, 6))
        plt.plot(parameter_values, silhouette_scores, 'bo-', linewidth=2, markersize=8)
        plt.xlabel(param_name, fontsize=12)
        plt.ylabel('Silhouette Score', fontsize=12)
        plt.title(title, fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)
        
        # Highlight best score
        best_idx = np.argmax(silhouette_scores)
        best_param = parameter_values[best_idx]
        best_score = silhouette_scores[best_idx]
        plt.scatter([best_param], [best_score], c='red', s=200, zorder=5)
        plt.annotate(f'Best: {best_score:.3f}', 
                    xy=(best_param, best_score),
                    xytext=(10, 10), textcoords='offset points',
                    fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved silhouette plot to {save_path}")
        else:
            save_path = os.path.join(self.output_dir, "silhouette_scores.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved silhouette plot to {save_path}")
        
        plt.close()
    
    def plot_cluster_purity(self, purity_details: Dict[str, Dict],
                           title: str = "Cluster Purity Analysis",
                           save_path: str = None) -> None:
        """
        Visualize cluster purity as a bar chart.
        
        Args:
            purity_details: Dictionary with cluster purity information
            title: Plot title
            save_path: Path to save the plot (optional)
        """
        cluster_ids = []
        purity_ratios = []
        dominant_labels = []
        
        for cluster_id, details in purity_details.items():
            cluster_ids.append(f"Cluster {cluster_id}")
            purity = details['dominant_count'] / details['cluster_size']
            purity_ratios.append(purity)
            dominant_labels.append(details['dominant_label'])
        
        # Create bar chart
        plt.figure(figsize=(12, 6))
        bars = plt.bar(cluster_ids, purity_ratios, color='steelblue', alpha=0.7)
        
        # Add value labels on bars
        for bar, purity in zip(bars, purity_ratios):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{purity:.2f}',
                    ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        # Add dominant label annotations
        for i, (bar, label) in enumerate(zip(bars, dominant_labels)):
            plt.text(bar.get_x() + bar.get_width()/2., 0.02,
                    f'{label[:15]}...' if len(label) > 15 else label,
                    ha='center', va='bottom', fontsize=8, rotation=45)
        
        plt.xlabel('Cluster ID', fontsize=12)
        plt.ylabel('Purity Ratio', fontsize=12)
        plt.title(title, fontsize=14, fontweight='bold')
        plt.ylim(0, 1.1)
        plt.grid(True, alpha=0.3, axis='y')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved purity plot to {save_path}")
        else:
            save_path = os.path.join(self.output_dir, "cluster_purity.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved purity plot to {save_path}")
        
        plt.close()
    
    def plot_cluster_sizes(self, cluster_info: Dict[str, Any],
                          title: str = "Cluster Size Distribution",
                          save_path: str = None) -> None:
        """
        Visualize cluster size distribution.
        
        Args:
            cluster_info: Dictionary with cluster information
            title: Plot title
            save_path: Path to save the plot (optional)
        """
        cluster_sizes = cluster_info.get('cluster_sizes', {})
        cluster_ids = [f"C{cid}" for cid in cluster_sizes.keys()]
        sizes = list(cluster_sizes.values())
        
        # Add noise if present
        if cluster_info.get('n_noise', 0) > 0:
            cluster_ids.append('Noise')
            sizes.append(cluster_info['n_noise'])
        
        plt.figure(figsize=(10, 6))
        colors = ['steelblue'] * len(cluster_sizes) + ['gray'] if cluster_info.get('n_noise', 0) > 0 else ['steelblue'] * len(cluster_sizes)
        bars = plt.bar(cluster_ids, sizes, color=colors, alpha=0.7)
        
        # Add value labels
        for bar, size in zip(bars, sizes):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{size}',
                    ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        plt.xlabel('Cluster', fontsize=12)
        plt.ylabel('Number of Samples', fontsize=12)
        plt.title(title, fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3, axis='y')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved cluster size plot to {save_path}")
        else:
            save_path = os.path.join(self.output_dir, "cluster_sizes.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved cluster size plot to {save_path}")
        
        plt.close()
    
    def create_summary_dashboard(self, evaluation_report: Dict[str, Any],
                                 feature_matrix: np.ndarray,
                                 cluster_labels: np.ndarray,
                                 save_path: str = None) -> None:
        """
        Create a summary dashboard with multiple visualizations.
        
        Args:
            evaluation_report: Evaluation report dictionary
            feature_matrix: Feature matrix
            cluster_labels: Cluster assignments
            save_path: Path to save the dashboard (optional)
        """
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Clustering Evaluation Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Cluster visualization (t-SNE)
        ax1 = axes[0, 0]
        if feature_matrix.shape[1] > 2:
            tsne = TSNE(n_components=2, random_state=42, perplexity=min(30, len(feature_matrix)-1))
            features_2d = tsne.fit_transform(feature_matrix)
        else:
            features_2d = feature_matrix
        
        unique_labels = set(cluster_labels)
        colors = plt.cm.tab20(np.linspace(0, 1, len(unique_labels)))
        
        for label, color in zip(unique_labels, colors):
            if label == -1:
                mask = cluster_labels == label
                ax1.scatter(features_2d[mask, 0], features_2d[mask, 1], 
                           c='black', marker='x', s=100, label='Noise', alpha=0.7)
            else:
                mask = cluster_labels == label
                ax1.scatter(features_2d[mask, 0], features_2d[mask, 1], 
                           c=[color], label=f'C{int(label)}', alpha=0.7, s=100)
        
        ax1.set_title('DBSCAN Clusters (t-SNE)', fontweight='bold')
        ax1.set_xlabel('Dimension 1')
        ax1.set_ylabel('Dimension 2')
        ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=8)
        ax1.grid(True, alpha=0.3)
        
        # 2. Cluster sizes
        ax2 = axes[0, 1]
        cluster_sizes = evaluation_report.get('cluster_sizes', {})
        cluster_ids = [f"C{cid}" for cid in cluster_sizes.keys()]
        sizes = list(cluster_sizes.values())
        
        if evaluation_report.get('n_noise', 0) > 0:
            cluster_ids.append('Noise')
            sizes.append(evaluation_report['n_noise'])
        
        colors = ['steelblue'] * len(cluster_sizes) + ['gray'] if evaluation_report.get('n_noise', 0) > 0 else ['steelblue'] * len(cluster_sizes)
        bars = ax2.bar(cluster_ids, sizes, color=colors, alpha=0.7)
        
        for bar, size in zip(bars, sizes):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{size}', ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        ax2.set_title('Cluster Size Distribution', fontweight='bold')
        ax2.set_xlabel('Cluster')
        ax2.set_ylabel('Number of Samples')
        ax2.grid(True, alpha=0.3, axis='y')
        
        # 3. Metrics summary
        ax3 = axes[1, 0]
        ax3.axis('off')
        
        purity_score = evaluation_report.get('purity_score')
        purity_display = f"{purity_score:.4f}" if purity_score is not None else "N/A"
        
        metrics_text = f"""
        CLUSTERING METRICS SUMMARY
        
        Total Samples: {evaluation_report['n_total']}
        Number of Clusters: {evaluation_report['n_clusters']}
        Noise Points: {evaluation_report['n_noise']} ({evaluation_report['noise_ratio']:.1%})
        
        Silhouette Score: {evaluation_report['silhouette_score']:.4f}
        Purity Score: {purity_display}
        """
        
        ax3.text(0.1, 0.5, metrics_text, fontsize=12, verticalalignment='center',
                family='monospace', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))
        
        # 4. Cluster purity (if available)
        ax4 = axes[1, 1]
        if evaluation_report.get('cluster_purity_details'):
            purity_details = evaluation_report['cluster_purity_details']
            cluster_ids = []
            purity_ratios = []
            
            for cluster_id, details in purity_details.items():
                cluster_ids.append(f"C{cluster_id}")
                purity = details['dominant_count'] / details['cluster_size']
                purity_ratios.append(purity)
            
            bars = ax4.bar(cluster_ids, purity_ratios, color='coral', alpha=0.7)
            
            for bar, purity in zip(bars, purity_ratios):
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height,
                        f'{purity:.2f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
            
            ax4.set_title('Cluster Purity', fontweight='bold')
            ax4.set_xlabel('Cluster')
            ax4.set_ylabel('Purity Ratio')
            ax4.set_ylim(0, 1.1)
            ax4.grid(True, alpha=0.3, axis='y')
        else:
            ax4.text(0.5, 0.5, 'Purity data not available\n(ground truth labels required)',
                    ha='center', va='center', fontsize=12, style='italic')
            ax4.set_title('Cluster Purity', fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved summary dashboard to {save_path}")
        else:
            save_path = os.path.join(self.output_dir, "evaluation_dashboard.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Saved summary dashboard to {save_path}")
        
        plt.close()


def generate_all_visualizations(evaluation_report: Dict[str, Any],
                                feature_matrix: np.ndarray,
                                cluster_labels: np.ndarray,
                                output_dir: str = "data/visualizations") -> None:
    """
    Generate all standard visualizations.
    
    Args:
        evaluation_report: Evaluation report dictionary
        feature_matrix: Feature matrix
        cluster_labels: Cluster assignments
        output_dir: Directory to save visualizations
    """
    visualizer = ClusterVisualizer(output_dir)
    
    print("\nGenerating visualizations...")
    
    # Cluster visualization
    visualizer.plot_clusters_2d(feature_matrix, cluster_labels)
    
    # Cluster size distribution
    cluster_info = {
        'cluster_sizes': evaluation_report.get('cluster_sizes', {}),
        'n_noise': evaluation_report.get('n_noise', 0)
    }
    visualizer.plot_cluster_sizes(cluster_info)
    
    # Cluster purity (if available)
    if evaluation_report.get('cluster_purity_details'):
        visualizer.plot_cluster_purity(evaluation_report['cluster_purity_details'])
    
    # Summary dashboard
    visualizer.create_summary_dashboard(evaluation_report, feature_matrix, cluster_labels)
    
    print(f"All visualizations saved to {output_dir}")


if __name__ == "__main__":
    # Test with sample data
    np.random.seed(42)
    
    # Create sample feature matrix
    feature_matrix = np.random.randn(20, 5)
    
    # Create sample cluster labels
    cluster_labels = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, -1, -1, -1, -1, -1])
    
    # Create sample evaluation report
    evaluation_report = {
        'n_total': 20,
        'n_clusters': 3,
        'n_noise': 5,
        'noise_ratio': 0.25,
        'silhouette_score': 0.75,
        'purity_score': 0.85,
        'cluster_sizes': {0: 5, 1: 5, 2: 5},
        'cluster_purity_details': {
            0: {'dominant_count': 4, 'cluster_size': 5, 'dominant_label': 'Campaign A'},
            1: {'dominant_count': 5, 'cluster_size': 5, 'dominant_label': 'Campaign B'},
            2: {'dominant_count': 4, 'cluster_size': 5, 'dominant_label': 'Campaign C'}
        }
    }
    
    print("Testing visualization module...")
    generate_all_visualizations(evaluation_report, feature_matrix, cluster_labels)
