import os
import importlib
import inspect
import logging
from typing import List, Type
from core.forensics.base import BaseParser, BaseDetector

logger = logging.getLogger(__name__)

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
        self.load_plugins()

    def load_plugins(self):
        """Discovers and loads all parser and detector plugins."""
        self.parsers = []
        self.detectors = []
        
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
            
        for filename in os.listdir(directory):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                full_module_name = f"{package_prefix}.{module_name}"
                
                try:
                    module = importlib.import_module(full_module_name)
                    # Reload module to pick up any changes if called repeatedly
                    importlib.reload(module)
                    
                    for name, obj in inspect.getmembers(module):
                        if inspect.isclass(obj) and issubclass(obj, base_class) and obj is not base_class:
                            try:
                                instance = obj()
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
