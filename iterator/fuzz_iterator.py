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
        get_cov = self.introspector.line_coverage(self.project)
        self.coverages.append(get_cov)

        logging.info(f"Project: {self.project}, Current coverage: {get_cov}")
        return

    def latest_cov(self):
        return self.coverages[-1]

    def should_regenerate(self) -> bool:
        """
        Determine if we should regenerate a new fuzz target or continue mutating.
        Returns True if coverage has stagnated (should regenerate),
        False if coverage is still improving (should mutate).
        """
        if len(self.coverages) < 2:  # Need at least 2 coverage values to compare
            return False

        current_cov = self.coverages[-1]
        previous_cov = self.coverages[-2]
        if current_cov - previous_cov > MIN_COVERAGE_IMPROVEMENT:
            return False  # Coverage is still improving, continue mutation

        return True  # Coverage has stagnated, should regenerate
