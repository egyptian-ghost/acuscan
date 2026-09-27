"""AcuScan startup customizations — suppress noisy warnings."""
import warnings

# Suppress BeautifulSoup XML warning
try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

# Suppress urllib3 InsecureRequestWarning
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

# Suppress other common warnings
warnings.filterwarnings("ignore", message=".*XMLParsedAsHTMLWarning.*")
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")