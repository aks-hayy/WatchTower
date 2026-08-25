"""Compatibility import for the unified historical Sigma engine."""

from core.forensics.sigma_engine import SigmaEngine, SigmaPredicate, validate_rule

__all__ = ["SigmaEngine", "SigmaPredicate", "validate_rule"]
