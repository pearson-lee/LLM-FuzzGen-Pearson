from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class TargetSaver:
    def __init__(self, base_dir: str = "./work/oss-fuzz/projects"):
        self.base_dir = Path(base_dir)

    def save_target(self, project_name: str, code: str) -> Path:
        target_dir = self.base_dir / project_name
        target_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%H%M%S")
        target_file = target_dir / \
            f"fuzz_{timestamp}_fuzzer.cc"

        target_file.write_text(code)
        return target_file
