"""
Infrastructure Fingerprint Builder
Extracts infrastructure features from scan records for clustering.
"""

import hashlib
import ipaddress
from typing import Dict, Any, Optional

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None


def get_ip_block(ip_str: str) -> Optional[str]:
    """
    Extract the /24 block from an IPv4 address.
    """
    try:
        # Check if valid IP
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            # Mask to /24
            network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            return str(network)
        elif ip.version == 6:
            # Mask to /48 for IPv6 as a rough equivalent
            network = ipaddress.ip_network(f"{ip_str}/48", strict=False)
            return str(network)
    except Exception:
        return None
    return None


def lookup_ip_info(ip_str: str) -> Dict[str, Any]:
    """
    Lookup ASN and Provider from IP address using ipwhois.
    """
    if not IPWhois or not ip_str:
        return {"asn": None, "provider": None}
        
    try:
        obj = IPWhois(ip_str)
        results = obj.lookup_rdap(depth=1)
        asn = results.get('asn')
        provider = results.get('network', {}).get('name') or results.get('asn_description')
        return {"asn": asn, "provider": provider}
    except Exception as e:
        print(f"Warning: IPWhois lookup failed for {ip_str}: {e}")
        return {"asn": None, "provider": None}


def build_fingerprint(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build infrastructure fingerprint from a scan record.
    
    Args:
        record: Dictionary containing scan record with fields:
            - url: Website URL
            - hosting_provider: Hosting provider name
            - asn: Autonomous System Number
            - ip_address: IP address
            - nameserver: Nameserver domain
            - ssl_issuer: SSL certificate issuer
            - dom_hash: DOM tag sequence hash (optional, will be computed if missing)
            - html_content: HTML content (optional, for computing dom_hash)
    
    Returns:
        Dictionary with fingerprint features:
            - ASN: Autonomous System Number
            - Provider: Hosting provider name
            - Nameserver: Nameserver domain
            - SSL: SSL certificate issuer
            - DOMHash: DOM tag sequence hash
            - IPBlock: /24 IP network block
    """
    fingerprint = {
        "ASN": None,
        "Provider": None,
        "Nameserver": None,
        "SSL": None,
        "DOMHash": None,
        "IPBlock": None
    }
    
    # Extract existing values
    asn_val = record.get("asn") or record.get("ASN")
    provider_val = record.get("hosting_provider") or record.get("Provider")
    ip_val = record.get("ip_address") or record.get("IP")
    
    # Perform IP->ASN lookup if missing
    if (not asn_val or not provider_val) and ip_val:
        lookup_results = lookup_ip_info(ip_val)
        if not asn_val:
            asn_val = lookup_results.get("asn")
        if not provider_val:
            provider_val = lookup_results.get("provider")
            
    # Extract IP Block
    if ip_val:
        fingerprint["IPBlock"] = get_ip_block(ip_val)
        
    fingerprint["ASN"] = asn_val
    fingerprint["Provider"] = provider_val
    
    # Extract Nameserver
    fingerprint["Nameserver"] = record.get("nameserver") or record.get("Nameserver")
    
    # Extract SSL Issuer
    fingerprint["SSL"] = record.get("ssl_issuer") or record.get("SSL")
    
    # Extract or compute DOM Hash
    dom_hash = record.get("dom_hash") or record.get("DOMHash")
    if dom_hash:
        fingerprint["DOMHash"] = dom_hash
    elif "html_content" in record and record["html_content"]:
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(record["html_content"], 'lxml')
            tag_sequence = extract_tag_sequence(soup)
            fingerprint["DOMHash"] = compute_dom_hash(tag_sequence)
        except Exception as e:
            print(f"Warning: Could not compute DOM hash for {record.get('url', 'unknown')}: {e}")
    
    # Handle missing values with defaults
    fingerprint["ASN"] = fingerprint["ASN"] if fingerprint["ASN"] is not None else 0
    fingerprint["Provider"] = fingerprint["Provider"] if fingerprint["Provider"] is not None else "Unknown"
    fingerprint["Nameserver"] = fingerprint["Nameserver"] if fingerprint["Nameserver"] is not None else "Unknown"
    fingerprint["SSL"] = fingerprint["SSL"] if fingerprint["SSL"] is not None else "Unknown"
    fingerprint["DOMHash"] = fingerprint["DOMHash"] if fingerprint["DOMHash"] is not None else ""
    fingerprint["IPBlock"] = fingerprint["IPBlock"] if fingerprint["IPBlock"] is not None else "Unknown"
    
    return fingerprint


def extract_tag_sequence(soup) -> str:
    """
    Extract tag sequence from HTML, ignoring text content and attributes.
    """
    tags = []
    
    def traverse(element):
        if hasattr(element, 'name') and element.name:
            tags.append(element.name)
            for child in element.children:
                traverse(child)
    
    traverse(soup)
    return ' '.join(tags)


def compute_dom_hash(tag_sequence: str) -> str:
    """
    Compute SHA-256 hash of DOM tag sequence.
    """
    return hashlib.sha256(tag_sequence.encode()).hexdigest()


if __name__ == "__main__":
    # Test with sample record
    sample_record = {
        "url": "https://example-scam.com",
        "hosting_provider": None,
        "asn": None,
        "ip_address": "8.8.8.8",
        "nameserver": "ns1.cloudflare.com",
        "ssl_issuer": "Let's Encrypt",
        "html_content": "<html><body><div><form><input></form></div></body></html>"
    }
    
    fingerprint = build_fingerprint(sample_record)
    print("Sample Fingerprint:")
    for key, value in fingerprint.items():
        print(f"  {key}: {value}")
