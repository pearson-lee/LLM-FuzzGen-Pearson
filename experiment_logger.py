import json
import logging
import threading
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ExperimentLogger:
    def __init__(
        self,
        system_name: str,
        project_name: str,
        run_id: str | None = None,
        output_dir: Path | None = None,
    ) -> None:
        self.system_name = system_name
        self.project_name = project_name
        self.run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = output_dir or Path(__file__).parent / "artifacts" / "metrics"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.output_dir / f"{self.run_id}.jsonl"
        self._lock = threading.Lock()

    def log_event(self, event: str, **payload: Any) -> None:
        record = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "run_id": self.run_id,
            "system": self.system_name,
            "project": self.project_name,
            "event": event,
        }
        record.update(self._normalize_payload(payload))

        try:
            with self._lock:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError as exc:
            logger.warning("Failed to write experiment log to %s: %s", self.log_path, exc)

    def _normalize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in payload.items():
            normalized[key] = self._normalize_value(value)
        return normalized

    def _normalize_value(self, value: Any) -> Any:
        if is_dataclass(value):
            return {k: self._normalize_value(v) for k, v in asdict(value).items()}
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, dict):
            return {str(k): self._normalize_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._normalize_value(v) for v in value]
        return value
