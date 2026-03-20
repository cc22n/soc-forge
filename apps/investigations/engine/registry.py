"""
Adapter registry — maps Source.slug to the adapter class that handles it.
"""

from .adapters.virustotal import VirusTotalAdapter
from .adapters.abuseipdb import AbuseIPDBAdapter
from .adapters.shodan import ShodanAdapter
from .adapters.greynoise import GreyNoiseAdapter
from .adapters.otx import OTXAdapter
from .adapters.abusech import ThreatFoxAdapter, URLhausAdapter, MalwareBazaarAdapter
from .adapters.others import (
    SecurityTrailsAdapter,
    SafeBrowsingAdapter,
    HybridAnalysisAdapter,
    URLScanAdapter,
    PulsediveAdapter,
    CriminalIPAdapter,
    IPQualityScoreAdapter,
    CensysAdapter,
    IPInfoAdapter,
)

# slug → adapter class
ADAPTER_REGISTRY: dict[str, type] = {
    "virustotal": VirusTotalAdapter,
    "abuseipdb": AbuseIPDBAdapter,
    "shodan": ShodanAdapter,
    "greynoise": GreyNoiseAdapter,
    "otx": OTXAdapter,
    "threatfox": ThreatFoxAdapter,
    "urlhaus": URLhausAdapter,
    "malware_bazaar": MalwareBazaarAdapter,
    "securitytrails": SecurityTrailsAdapter,
    "google_safebrowsing": SafeBrowsingAdapter,
    "hybrid_analysis": HybridAnalysisAdapter,
    "urlscan": URLScanAdapter,
    "pulsedive": PulsediveAdapter,
    "criminal_ip": CriminalIPAdapter,
    "ipqualityscore": IPQualityScoreAdapter,
    "censys": CensysAdapter,
    "ipinfo": IPInfoAdapter,
}


def get_adapter(source_slug: str):
    """Get an instantiated adapter for a source slug."""
    adapter_class = ADAPTER_REGISTRY.get(source_slug)
    if adapter_class is None:
        return None
    return adapter_class()


def get_all_adapters():
    """Get all registered adapter instances."""
    return {slug: cls() for slug, cls in ADAPTER_REGISTRY.items()}
