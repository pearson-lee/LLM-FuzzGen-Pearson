import logging

from config.config import MIN_COVERAGE_IMPROVEMENT
from external.introspector import Introspector

logger = logging.getLogger(__name__)


class FuzzIterator:
    def __init__(self, project: str):
        self.project = project
        self.introspector = Introspector()
        self.coverages: list[float] = []

    def record_cov(self):
        cov = self.introspector.line_coverage(self.project)
        if cov is None or cov == 0:
            logger.warning("Coverage is None, skipping record.")
            return

        self.coverages.append(cov)
        logger.info(f"Project: {self.project}, Current coverage: {cov}")
        return

    def latest_cov(self):
        return self.coverages[-1]

    def first_cov(self):
        return self.coverages[0]

    def should_regenerate(self) -> bool:
        """
        Determine if we should regenerate a new fuzz target or continue mutating.
        Returns True if coverage has stagnated (should regenerate),
        False if coverage is still improving (should mutate).
        """
        # Need at least 4 coverage records to evaluate three consecutive improvements
        if len(self.coverages) < 4:
            return False

        # Compute the last three coverage deltas
        deltas = [self.coverages[i] - self.coverages[i - 1] for i in range(-3, 0)]
        # If all three improvements are below the threshold, stagnation => regenerate
        if all(delta < MIN_COVERAGE_IMPROVEMENT for delta in deltas):
            return True
        # Otherwise, continue mutating
        return False
