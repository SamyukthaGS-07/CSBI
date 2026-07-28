"""
HTML Template Similarity Module
Computes structural similarity between HTML documents using tag sequences.
"""

from typing import List, Tuple
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np


def extract_tag_sequence(html_content: str) -> str:
    """
    Extract tag sequence from HTML, ignoring text content and attributes.
    
    Args:
        html_content: Raw HTML string
    
    Returns:
        String representation of tag sequence (space-separated tag names)
    """
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        tags = []
        
        def traverse(element):
            if hasattr(element, 'name') and element.name:
                tags.append(element.name)
                for child in element.children:
                    traverse(child)
        
        traverse(soup)
        return ' '.join(tags)
    except Exception as e:
        print(f"Warning: Could not parse HTML: {e}")
        return ""


def compute_similarity_matrix(html_contents: List[str]) -> np.ndarray:
    """
    Compute pairwise similarity matrix for multiple HTML documents.
    
    Args:
        html_contents: List of HTML content strings
    
    Returns:
        NxN similarity matrix where N is the number of documents
    """
    # Extract tag sequences
    tag_sequences = [extract_tag_sequence(html) for html in html_contents]
    
    # Filter out empty sequences
    valid_indices = [i for i, seq in enumerate(tag_sequences) if seq]
    if len(valid_indices) < 2:
        # If fewer than 2 valid documents, return zeros
        return np.zeros((len(html_contents), len(html_contents)))
    
    # Use TF-IDF to convert tag sequences to vectors
    vectorizer = TfidfVectorizer(tokenizer=lambda x: x.split(), token_pattern=None)
    tfidf_matrix = vectorizer.fit_transform([tag_sequences[i] for i in valid_indices])
    
    # Compute cosine similarity
    similarity_matrix = cosine_similarity(tfidf_matrix)
    
    # Build full NxN matrix
    full_matrix = np.zeros((len(html_contents), len(html_contents)))
    for i, idx_i in enumerate(valid_indices):
        for j, idx_j in enumerate(valid_indices):
            full_matrix[idx_i, idx_j] = similarity_matrix[i, j]
    
    return full_matrix


def compute_similarity(html1: str, html2: str) -> float:
    """
    Compute similarity between two HTML documents.
    
    Args:
        html1: First HTML content
        html2: Second HTML content
    
    Returns:
        Similarity score between 0 and 1
    """
    similarity_matrix = compute_similarity_matrix([html1, html2])
    return similarity_matrix[0, 1]


def get_average_similarity(html_contents: List[str]) -> float:
    """
    Compute average pairwise similarity across all documents.
    
    Args:
        html_contents: List of HTML content strings
    
    Returns:
        Average similarity score
    """
    similarity_matrix = compute_similarity_matrix(html_contents)
    # Get upper triangle (excluding diagonal)
    upper_triangle = similarity_matrix[np.triu_indices_from(similarity_matrix, k=1)]
    if len(upper_triangle) == 0:
        return 0.0
    return np.mean(upper_triangle)


if __name__ == "__main__":
    # Test with sample HTML
    html1 = """
    <html>
        <body>
            <div class="container">
                <form>
                    <input type="text">
                    <button>Submit</button>
                </form>
            </div>
        </body>
    </html>
    """
    
    html2 = """
    <html>
        <body>
            <div class="wrapper">
                <form>
                    <input type="email">
                    <button>Send</button>
                </form>
            </div>
        </body>
    </html>
    """
    
    html3 = """
    <html>
        <body>
            <p>Some text</p>
            <a href="#">Link</a>
        </body>
    </html>
    """
    
    print("Testing HTML Similarity:")
    print(f"Similarity (html1, html2): {compute_similarity(html1, html2):.3f}")
    print(f"Similarity (html1, html3): {compute_similarity(html1, html3):.3f}")
    print(f"Similarity (html2, html3): {compute_similarity(html2, html3):.3f}")
    
    print("\nTag Sequences:")
    print(f"html1: {extract_tag_sequence(html1)}")
    print(f"html2: {extract_tag_sequence(html2)}")
    print(f"html3: {extract_tag_sequence(html3)}")
