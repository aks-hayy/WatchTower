import os
import logging
from typing import List, Dict, Any
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

logger = logging.getLogger("sigma_engine")

class SigmaEngine:
    """
    Integrates Sigma rules for custom threat detection in Watchtower.
    Uses pySigma to compile rules into SQL queries or match against flow data.
    """

    def __init__(self, rules_dir: str = "rules/sigma"):
        self.rules_dir = rules_dir
        os.makedirs(self.rules_dir, exist_ok=True)
        self.rules = None
        # Initialize backend without complex pipelines for now to ensure stability
        try:
            self.backend = sqliteBackend()
        except Exception as e:
            logger.error("Failed to initialize Sigma SQLite backend: %s", e)
            self.backend = None
        self._load_rules()

    def _load_rules(self):
        """Load all Sigma rules from the rules directory."""
        try:
            if not os.path.exists(self.rules_dir) or not os.listdir(self.rules_dir):
                logger.info("No Sigma rules found in %s", self.rules_dir)
                return

            self.rules = SigmaCollection.from_directory(self.rules_dir)
            logger.info("Loaded %d Sigma rules", len(self.rules))
        except Exception as e:
            logger.error("Failed to load Sigma rules: %s", e)

    def get_detection_queries(self) -> List[str]:
        """Convert Sigma rules into SQLite queries for historical scanning."""
        if not self.rules or not self.backend:
            return []
        
        try:
            return self.backend.convert(self.rules)
        except Exception as e:
            logger.error("Failed to convert Sigma rules to SQL: %s", e)
            return []

    def scan_database(self, db_instance):
        """Scan the flows table in the database using Sigma rules converted to SQL."""
        # Future implementation for historical DB scanning
        pass
