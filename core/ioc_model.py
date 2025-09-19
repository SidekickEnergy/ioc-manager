# core/ioc_model.py

from datetime import datetime
from core.ioc_processor import detect_ioc_type


class IoC:
    def __init__(self, value: str):
        self.value = value.strip().lower()
        self.type = detect_ioc_type(self.value)
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.enrichment = {}

    def enrich_with(self, source_name: str, data: dict):
        """Attach enrichment data from a specific source."""
        self.enrichment[source_name] = data

    def summary(self):
        lines = [f"[+] IoC: {self.value} (Type: {self.type})"]
        for source, data in self.enrichment.items():
            lines.append(f"  - Enriched via {source}:")

            if isinstance(data, dict):
                for key, value in data.items():
                    if key == "pulses" and isinstance(value, list):
                        for pulse in value:
                            lines.append("    • Pulse:")
                            for pk, pv in pulse.items():
                                if isinstance(pv, list):
                                    lines.append(f"      • {pk}:")
                                    for item in pv:
                                        lines.append(f"        - {item}")
                                else:
                                    lines.append(f"      • {pk}: {pv}")
                    elif isinstance(value, list):
                        lines.append(f"    • {key}:")
                        for item in value:
                            lines.append(f"      - {item}")
                    else:
                        lines.append(f"    • {key}: {value}")
            else:
                lines.append(f"    • {data}")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Return dict representation for API output."""
        return {
            "ioc": self.value,
            "type": self.type,
            "timestamp": self.timestamp,
            "enrichment": self.enrichment
        }
