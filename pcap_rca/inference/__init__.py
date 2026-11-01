"""Root-cause inference: turn detected events into diagnoses."""
from .rules import RULES, Diagnosis, infer

__all__ = ["Diagnosis", "RULES", "infer"]
