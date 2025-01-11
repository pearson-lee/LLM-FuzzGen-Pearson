from pathlib import Path
from datetime import datetime
import logging
import config

logger = logging.getLogger(__name__)


class TargetSaver:
    LANGUAGE_EXTENSIONS = {
        'c': '.c',
        'c++': '.cc',
        'cpp': '.cc'
    }
    def __init__(self):
        self.base_dir = Path(config.OSS_FUZZ_PATH) / "projects"

    def save_target(self, project_name: str, code: str, language: str) -> Path:
        target_dir = self.base_dir / project_name
        target_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%H%M%S")
        extension = self.LANGUAGE_EXTENSIONS[language.lower()]
        target_file = target_dir / f"fuzz_{timestamp}_fuzzer{extension}"

        target_file.write_text(code)
        return target_file
