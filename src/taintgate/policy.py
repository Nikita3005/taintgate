from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    block_at: int = 90
    review_at: int = 60
    denied_tools: frozenset[str] = field(default_factory=frozenset)
    review_tools: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not 0 <= self.review_at <= self.block_at <= 100:
            raise ValueError("thresholds must satisfy 0 <= review_at <= block_at <= 100")
