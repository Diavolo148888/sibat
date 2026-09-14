"""SIBAT — scope-locked offensive recon framework.

SIBAT is a recon and attack-surface mapping framework intended solely for
use against systems you own or are explicitly authorized to test (your own
lab, authorized engagements, bug bounty programs with permission).

Every network operation passes through the ScopeGuard. If a target is not
inside the loaded rules of engagement, the weapon refuses to fire.
"""

__version__ = "1.4.0"
UA = f"SIBAT/{__version__} (authorized-scope recon; contact via program policy)"
