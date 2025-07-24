import logging

from config.config import MIN_COVERAGE_IMPROVEMENT
from external.oss_fuzz import OSSFuzz, TotalCoverageSummary

logger = logging.getLogger(__name__)


class FuzzIterator:
    def __init__(self, project: str, oss_fuzz: OSSFuzz):
        self.project = project
        self.oss_fuzz = oss_fuzz
        self.coverages: list[TotalCoverageSummary] = []

    def record_cov(self):
        cov = self.oss_fuzz.get_coverage_summary(self.project, exclude_target=True)
        if not cov:
            logger.warning("Coverage is None, skipping record.")
            return

        self.coverages.append(cov)
        line_percent = cov.lines.percent if cov.lines else "N/A"
        branch_percent = cov.branches.percent if cov.branches else "N/A"
        logger.info(f"Project: {self.project}, Current coverage: Lines={line_percent}%, Branches={branch_percent}%")
        return

    def clean_cov(self):
        self.coverages.clear()

    def latest_cov(self) -> TotalCoverageSummary | None:
        if not self.coverages:
            logger.warning(f"[{self.project}] Attempted to get latest coverage, but no coverages recorded yet. Returning None.")
            return None
        return self.coverages[-1]

    def first_cov(self) -> TotalCoverageSummary | None:
        if not self.coverages:
            logger.warning(f"[{self.project}] Attempted to get first coverage, but no coverages recorded yet. Returning None.")
            return None
        return self.coverages[0]

    def should_regenerate(self) -> bool:
        """
        Determine if we should regenerate a new fuzz target or continue mutating.
        Returns True if coverage has stagnated (should regenerate),
        False if coverage is still improving (should mutate).
        """
        logger.info(f"[{self.project}] Current line coverage percentages: {[c.lines.percent for c in self.coverages if c.lines]}")

        # Need at least 4 coverage records to evaluate three consecutive improvements.
        if len(self.coverages) < 4:
            return False

        # Safely get the line coverage for the last four records.
        last_four_lines = [cov.lines.percent for cov in self.coverages[-4:] if cov and cov.lines]

        # If we don't have four valid line coverage data points, we can't check for stagnation.
        if len(last_four_lines) < 4:
            return False

        # Check if the last three consecutive improvements are all below the minimum threshold.
        stagnated = all(last_four_lines[i] - last_four_lines[i - 1] < MIN_COVERAGE_IMPROVEMENT for i in range(1, 4))

        return stagnated
