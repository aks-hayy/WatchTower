import os
import importlib
import inspect
import logging
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Type
from core.forensics.base import BaseParser, BaseDetector

logger = logging.getLogger(__name__)


@dataclass
class PluginHealth:
    name: str
    plugin_type: str
    enabled: bool
    valid: bool = True
    errors: int = 0
    last_error: str = ""
    detector_id: str = ""
    contract_version: int = 1
    calibrated: bool = False
    calibration_level: str = "NOT_APPLICABLE"
    calibration: List[Dict[str, Any]] = field(default_factory=list)

class PluginLoader:
    """Dynamically loads protocol parsers and threat detectors from the plugins directory."""
    
    def __init__(self, plugins_dir: str = None):
        if plugins_dir is None:
            # Default to the plugins directory in the same package
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.plugins_dir = os.path.join(base_dir, "plugins")
        else:
            self.plugins_dir = plugins_dir
            
        self.parsers: List[BaseParser] = []
        self.detectors: List[BaseDetector] = []
        self.health: Dict[str, PluginHealth] = {}
        self.load_plugins()

    def load_plugins(self):
        """Discovers and loads all parser and detector plugins."""
        self.parsers = []
        self.detectors = []
        self.health = {}
        self._detector_ids = set()
        
        # Ensure plugins directories exist
        parsers_dir = os.path.join(self.plugins_dir, "parsers")
        detectors_dir = os.path.join(self.plugins_dir, "detectors")
        
        if not os.path.exists(parsers_dir):
            os.makedirs(parsers_dir, exist_ok=True)
            with open(os.path.join(parsers_dir, "__init__.py"), "w") as f: pass
        if not os.path.exists(detectors_dir):
            os.makedirs(detectors_dir, exist_ok=True)
            with open(os.path.join(detectors_dir, "__init__.py"), "w") as f: pass
        if not os.path.exists(os.path.join(self.plugins_dir, "__init__.py")):
            with open(os.path.join(self.plugins_dir, "__init__.py"), "w") as f: pass
            
        self._load_from_directory(parsers_dir, "core.forensics.plugins.parsers", BaseParser, self.parsers)
        self._load_from_directory(detectors_dir, "core.forensics.plugins.detectors", BaseDetector, self.detectors)

    def _load_from_directory(self, directory: str, package_prefix: str, base_class: Type, target_list: List):
        if not os.path.exists(directory):
            return
            
        for filename in sorted(os.listdir(directory)):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                full_module_name = f"{package_prefix}.{module_name}"
                
                try:
                    module = importlib.import_module(full_module_name)
                    # Reload module to pick up any changes if called repeatedly
                    importlib.reload(module)
                    
                    for name, obj in sorted(inspect.getmembers(module), key=lambda item: item[0]):
                        if inspect.isclass(obj) and issubclass(obj, base_class) and obj is not base_class:
                            try:
                                instance = obj()
                                validation_errors = list(instance.validate() or [])
                                manifest = getattr(instance, "manifest", None)
                                if manifest is not None and manifest.detector_id in self._detector_ids:
                                    validation_errors.append(f"duplicate detector_id: {manifest.detector_id}")
                                if manifest is not None and not validation_errors:
                                    self._detector_ids.add(manifest.detector_id)
                                key = f"{base_class.__name__}:{instance.name}"
                                effective_calibrated = False
                                calibration_level = "NOT_APPLICABLE"
                                calibration = []
                                if manifest is not None:
                                    try:
                                        from core.detection.scoring import ScoringConfig

                                        config = ScoringConfig()
                                        for finding_type in manifest.finding_types:
                                            profile = config.profile_for(manifest.detector_id, finding_type, manifest.version)
                                            metrics = {}
                                            if profile.attestation_digest:
                                                from core.calibration.attestations import ATTESTATION_DIR
                                                attestation_path = ATTESTATION_DIR / f"{profile.attestation_digest}.json"
                                                if attestation_path.is_file():
                                                    metrics = json.loads(attestation_path.read_text(encoding="utf-8")).get("metrics") or {}
                                            if profile.calibration_level == "FIELD_CALIBRATED":
                                                cap = profile.max_contribution
                                            elif profile.calibration_level == "CORPUS_VALIDATED":
                                                cap = min(profile.max_contribution, config.corpus_validated_finding_cap)
                                            else:
                                                cap = config.uncalibrated_finding_cap
                                            calibration.append({
                                                "finding_type": finding_type,
                                                "calibration_level": profile.calibration_level,
                                                "effective_cap": cap,
                                                "attestation_digest": profile.attestation_digest,
                                                "metrics": metrics,
                                                "stale_reason": profile.stale_reason,
                                            })
                                        levels = {item["calibration_level"] for item in calibration}
                                        calibration_level = next(iter(levels)) if len(levels) == 1 else "MIXED"
                                        effective_calibrated = bool(calibration) and levels == {"FIELD_CALIBRATED"}
                                    except Exception as exc:
                                        logger.warning("Unable to resolve effective calibration for %s: %s", manifest.detector_id, exc)
                                        effective_calibrated = False
                                        calibration_level = "UNCALIBRATED"
                                self.health[key] = PluginHealth(
                                    name=instance.name,
                                    plugin_type="parser" if base_class is BaseParser else "detector",
                                    enabled=bool(instance.enabled),
                                    valid=not validation_errors,
                                    errors=len(validation_errors),
                                    last_error="; ".join(validation_errors),
                                    detector_id=getattr(manifest, "detector_id", "") if manifest else "",
                                    contract_version=getattr(manifest, "contract_version", 1) if manifest else 1,
                                    calibrated=effective_calibrated,
                                    calibration_level=calibration_level,
                                    calibration=calibration,
                                )
                                if not validation_errors:
                                    target_list.append(instance)
                                logger.info(f"Loaded plugin: {obj.name} from {filename}")
                            except Exception as e:
                                logger.error(f"Failed to instantiate plugin {name}: {e}")
                except Exception as e:
                    logger.error(f"Failed to load module {full_module_name}: {e}")

    def get_parsers(self) -> List[BaseParser]:
        return self.parsers

    def get_detectors(self) -> List[BaseDetector]:
        return self.detectors

    def reset(self, source: str = None) -> None:
        for plugin in [*self.parsers, *self.detectors]:
            try:
                plugin.reset(source)
            except Exception as exc:
                self.record_error(plugin, exc)

    def record_error(self, plugin, error: Exception) -> None:
        key = f"{'BaseParser' if isinstance(plugin, BaseParser) else 'BaseDetector'}:{plugin.name}"
        health = self.health.get(key)
        if health:
            health.errors += 1
            health.last_error = str(error)

    def list_plugins(self) -> Dict[str, Dict]:
        return {
            key: {
                "name": item.name,
                "type": item.plugin_type,
                "enabled": item.enabled,
                "valid": item.valid,
                "errors": item.errors,
                "last_error": item.last_error,
                "description": f"{item.plugin_type.title()} plugin",
                "api_version": next(
                    (plugin.api_version for plugin in [*self.parsers, *self.detectors] if plugin.name == item.name),
                    1,
                ),
                "supported_link_types": list(next(
                    (plugin.supported_link_types for plugin in [*self.parsers, *self.detectors] if plugin.name == item.name),
                    (),
                )),
                "detector_id": item.detector_id,
                "contract_version": item.contract_version,
                "calibrated": item.calibrated,
                "calibration_level": item.calibration_level,
                "calibration": item.calibration,
            }
            for key, item in sorted(self.health.items())
        }
