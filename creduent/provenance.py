import logging
from enum import Enum
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)


class ReversibilityClass(str, Enum):
    """OWASP AISVS v1.0 (C9.2.3) Reversibility Classification Vocabulary."""

    READ_ONLY = "read_only"
    REVERSIBLE = "reversible"
    EXTERNALLY_REVERSIBLE = "externally_reversible"
    IRREVERSIBLE = "irreversible"

    # Alias mappings for legacy / standard names
    NON_RECOVERABLE = "irreversible"
    RECOVERABLE_LOCAL = "reversible"


# Precedence ranking for worst-case reduction (higher index = higher severity / risk)
REVERSIBILITY_PRECEDENCE = [
    ReversibilityClass.READ_ONLY,
    ReversibilityClass.REVERSIBLE,
    ReversibilityClass.EXTERNALLY_REVERSIBLE,
    ReversibilityClass.IRREVERSIBLE,
]


class ProvenanceGuard:
    """Provenance Guard enforcing entry-boundary normalization for tool reversibility classes.

    Ensures that any tool metadata that is missing, unclassified, or self-asserted by a tool
    object without trusted Creduent policy/registry binding resolves explicitly to IRREVERSIBLE.
    """

    def __init__(self, trusted_registries: Optional[Set[str]] = None):
        self.trusted_registries = trusted_registries or {"https://creduent.idevsec.com"}

    def normalize(
        self,
        tool_metadata: Optional[Dict[str, Any]],
        provenance_source: Optional[str] = None,
        is_registry_bound: bool = False,
    ) -> str:
        """Normalizes tool reversibility metadata at the adapter entry boundary.

        Args:
            tool_metadata: Metadata dictionary associated with a framework tool.
            provenance_source: Source URI or registry URL declaring the reversibility class.
            is_registry_bound: True if the class was bound via a verified Creduent policy document.

        Returns:
            str: Normalized reversibility class ('read_only', 'reversible', 'externally_reversible', or 'irreversible').
        """
        if not tool_metadata or not isinstance(tool_metadata, dict):
            logger.warning("[ProvenanceGuard] Tool metadata is missing or invalid. Normalizing to IRREVERSIBLE (fail-closed).")
            return ReversibilityClass.IRREVERSIBLE.value

        raw_class = tool_metadata.get("reversibility_class") or tool_metadata.get("declared_effect")

        # 1. Unclassified / Missing -> Fail-closed to IRREVERSIBLE
        if not raw_class or not isinstance(raw_class, str):
            logger.warning(
                f"[ProvenanceGuard] Tool '{tool_metadata.get('name', 'unknown')}' has no declared reversibility class. "
                "Normalizing to IRREVERSIBLE (fail-closed)."
            )
            return ReversibilityClass.IRREVERSIBLE.value

        raw_class_clean = raw_class.strip().lower()

        # 2. Map legacy / alternative vocabulary to standard AISVS C9.2.3 classes
        normalized_class = self._canonicalize_vocabulary(raw_class_clean)
        if not normalized_class:
            logger.warning(
                f"[ProvenanceGuard] Tool '{tool_metadata.get('name', 'unknown')}' declared unknown class '{raw_class}'. "
                "Normalizing to IRREVERSIBLE (fail-closed)."
            )
            return ReversibilityClass.IRREVERSIBLE.value

        # 3. Provenance Check: Self-Assertion Guard
        # If the class was self-asserted by the tool object at runtime rather than bound by a trusted registry/policy,
        # treat as untrusted and resolve to IRREVERSIBLE.
        if not is_registry_bound and (not provenance_source or provenance_source not in self.trusted_registries):
            logger.info(
                f"[ProvenanceGuard] Tool '{tool_metadata.get('name', 'unknown')}' class '{normalized_class}' is self-asserted without trusted policy binding. "
                "Overriding to IRREVERSIBLE to prevent self-assertion bypass."
            )
            return ReversibilityClass.IRREVERSIBLE.value

        return normalized_class

    @staticmethod
    def _canonicalize_vocabulary(raw_class: str) -> Optional[str]:
        mapping = {
            "read_only": ReversibilityClass.READ_ONLY.value,
            "readonly": ReversibilityClass.READ_ONLY.value,
            "reversible": ReversibilityClass.REVERSIBLE.value,
            "recoverable_local": ReversibilityClass.REVERSIBLE.value,
            "externally_reversible": ReversibilityClass.EXTERNALLY_REVERSIBLE.value,
            "irreversible": ReversibilityClass.IRREVERSIBLE.value,
            "non_recoverable": ReversibilityClass.IRREVERSIBLE.value,
        }
        return mapping.get(raw_class)


# Default global instance
default_provenance_guard = ProvenanceGuard()


def normalize_reversibility_class(
    tool_metadata: Optional[Dict[str, Any]],
    provenance_source: Optional[str] = None,
    is_registry_bound: bool = False,
) -> str:
    """Helper function to normalize tool reversibility metadata at the adapter boundary."""
    return default_provenance_guard.normalize(
        tool_metadata=tool_metadata,
        provenance_source=provenance_source,
        is_registry_bound=is_registry_bound,
    )
