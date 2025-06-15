import logging
from math import e

from config.config import MIN_COVERAGE_IMPROVEMENT
from external.oss_fuzz import OSSFuzz

logger = logging.getLogger(__name__)


class FuzzIterator:
    def __init__(self, project: str, oss_fuzz: OSSFuzz):
        self.project = project
        self.oss_fuzz = oss_fuzz
        self.coverages: list[float] = []

    def record_cov(self):
        cov = self.oss_fuzz.get_coverage_summary(self.project, exclude_target=True).lines.percent
        if cov is None or cov == 0:
            logger.warning("Coverage is None, skipping record.")
            return

        self.coverages.append(cov)
        logger.info(f"Project: {self.project}, Current coverage: {cov}")
        return

    def clean_cov(self):
        self.coverages.clear()

    def latest_cov(self):
        if not self.coverages:
            logger.warning(f"[{self.project}] Attempted to get latest coverage, but no coverages recorded yet. Returning 0.0.")
            return 0.0
        return self.coverages[-1]

    def first_cov(self):
        if not self.coverages:
            logger.warning(f"[{self.project}] Attempted to get first coverage, but no coverages recorded yet. Returning 0.0.")
            return 0.0
        return self.coverages[0]

    def should_regenerate(self) -> bool:
        """
        Determine if we should regenerate a new fuzz target or continue mutating.
        Returns True if coverage has stagnated (should regenerate),
        False if coverage is still improving (should mutate).
        """
        logger.info(f"[{self.project}] Current coverage array: {self.coverages}")

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
