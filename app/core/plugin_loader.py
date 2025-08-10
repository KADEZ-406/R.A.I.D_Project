"""
Plugin Loader for R.A.I.D Scanner
Handles dynamic plugin discovery, loading, and execution
"""

import importlib
import importlib.util
import inspect
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.core.model import Finding

logger = logging.getLogger(__name__)


class PluginLoader:
    """Loads and manages security plugins."""
    
    def __init__(self, plugins_dir: str = "app/plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.loaded_plugins: Dict[str, Any] = {}
        self.plugin_metadata: Dict[str, Dict] = {}
        self.logger = logging.getLogger(__name__)
        
    def discover_plugins(self) -> List[str]:
        """Discover available plugin files."""
        plugin_files = []
        
        if not self.plugins_dir.exists():
            self.logger.warning(f"Plugins directory {self.plugins_dir} does not exist")
            return plugin_files
        
        # Find all .py files that aren't __init__.py or plugin_generator.py
        for plugin_file in self.plugins_dir.glob("*.py"):
            if plugin_file.name in ["__init__.py", "plugin_generator.py"]:
                continue
            plugin_files.append(plugin_file.stem)
        
        self.logger.info(f"Discovered {len(plugin_files)} plugins: {plugin_files}")
        return plugin_files
    
    def load_plugin(self, plugin_name: str) -> bool:
        """Load a single plugin by name."""
        try:
            plugin_path = self.plugins_dir / f"{plugin_name}.py"
            if not plugin_path.exists():
                self.logger.error(f"Plugin file not found: {plugin_path}")
                return False
            
            # Load the module
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if spec is None or spec.loader is None:
                self.logger.error(f"Could not load spec for plugin: {plugin_name}")
                return False
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Validate plugin structure
            if not hasattr(module, "METADATA"):
                self.logger.error(f"Plugin {plugin_name} missing METADATA")
                return False
            
            if not hasattr(module, "run"):
                self.logger.error(f"Plugin {plugin_name} missing run function")
                return False
            
            # Validate metadata (support new schema)
            metadata = module.METADATA
            # Accept either legacy fields or new required keys
            legacy_ok = all(k in metadata for k in ["name", "version", "description", "severity", "required_mode"]) if isinstance(metadata, dict) else False
            new_ok = all(k in metadata for k in ["id", "name", "category", "severity_hint", "required_mode", "implemented"]) if isinstance(metadata, dict) else False
            if not (legacy_ok or new_ok):
                self.logger.error(f"Plugin {plugin_name} metadata does not satisfy required fields (legacy or new schema)")
                return False
            
            # Validate run function signature
            run_func = module.run
            if not inspect.iscoroutinefunction(run_func):
                self.logger.error(f"Plugin {plugin_name} run function must be async")
                return False
            
            # Store the loaded plugin
            self.loaded_plugins[plugin_name] = module
            self.plugin_metadata[plugin_name] = metadata
            
            self.logger.info(f"Successfully loaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading plugin {plugin_name}: {e}")
            return False
    
    def load_all_plugins(self) -> int:
        """Load all discovered plugins."""
        plugin_names = self.discover_plugins()
        loaded_count = 0
        
        for plugin_name in plugin_names:
            if self.load_plugin(plugin_name):
                loaded_count += 1
        
        self.logger.info(f"Loaded {loaded_count}/{len(plugin_names)} plugins")
        return loaded_count
    
    def get_plugin(self, plugin_name: str) -> Optional[Any]:
        """Get a loaded plugin by name."""
        return self.loaded_plugins.get(plugin_name)
    
    def get_plugins_by_mode(self, mode: str) -> Dict[str, Any]:
        """Get plugins that can run in the specified mode."""
        compatible_plugins = {}
        
        for plugin_name, metadata in self.plugin_metadata.items():
            required_mode = metadata.get("required_mode", "safe")
            
            # Check mode compatibility
            if required_mode == "both" or required_mode == mode:
                compatible_plugins[plugin_name] = self.loaded_plugins[plugin_name]
            elif mode == "audit" and required_mode in ["safe", "lab"]:
                # Audit mode can run safe and lab plugins
                compatible_plugins[plugin_name] = self.loaded_plugins[plugin_name]
            elif mode == "lab" and required_mode == "safe":
                # Lab mode can run safe plugins
                compatible_plugins[plugin_name] = self.loaded_plugins[plugin_name]
        
        return compatible_plugins
    
    def get_plugin_metadata(self, plugin_name: str) -> Optional[Dict]:
        """Get metadata for a specific plugin."""
        return self.plugin_metadata.get(plugin_name)
    
    def filter_plugins(self, 
                      plugin_list: Optional[List[str]] = None,
                      mode: str = "safe",
                      categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """Filter plugins based on criteria."""
        # Start with mode-compatible plugins
        filtered_plugins = self.get_plugins_by_mode(mode)
        
        # Filter by specific plugin names if provided
        if plugin_list:
            filtered_plugins = {
                name: plugin for name, plugin in filtered_plugins.items()
                if name in plugin_list
            }
        
        # Filter by categories if provided
        if categories:
            category_filtered = {}
            for name, plugin in filtered_plugins.items():
                metadata = self.plugin_metadata.get(name, {})
                plugin_category = metadata.get("category", "").lower()
                if any(cat.lower() in plugin_category for cat in categories):
                    category_filtered[name] = plugin
            filtered_plugins = category_filtered
        
        return filtered_plugins
    
    def validate_finding(self, finding: Finding) -> bool:
        """Validate a finding object."""
        try:
            # Basic validation is done in Finding.__post_init__
            # Additional validation can be added here
            if not finding.id or not finding.name:
                return False
            
            if not finding.target or not finding.endpoint:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating finding: {e}")
            return False
    
    def get_plugin_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded plugins."""
        stats = {
            "total_plugins": len(self.loaded_plugins),
            "by_mode": {},
            "by_category": {},
            "by_severity": {}
        }
        
        for plugin_name, metadata in self.plugin_metadata.items():
            # Count by mode
            mode = metadata.get("required_mode", "safe")
            stats["by_mode"][mode] = stats["by_mode"].get(mode, 0) + 1
            
            # Count by category
            category = metadata.get("category", "unknown")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            # Count by severity
            severity = metadata.get("severity", "info")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
        
        return stats 