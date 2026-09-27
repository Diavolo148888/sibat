"""Recon engine — the Phase 1 heart of SIBAT.

Every stage is scope-guarded. Every stage yields Finding objects.
Stages: resolve -> ports -> services -> web -> dirs.
"""
