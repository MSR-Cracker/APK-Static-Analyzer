"""Abstract base class for static analysis detectors."""
from abc import ABC, abstractmethod
from typing import Any, List
from analyzer.models import DexMethod


class BaseDetector(ABC):
    """Base detector interface."""

    def __init__(self, methods: List[DexMethod]):
        self.methods = methods

    @abstractmethod
    def detect(self) -> Any:
        pass
