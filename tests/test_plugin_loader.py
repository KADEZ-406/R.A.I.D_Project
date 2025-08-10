import inspect

from app.core.plugin_loader import PluginLoader


def test_plugins_have_metadata_and_run_signature():
    loader = PluginLoader()
    count = loader.load_all_plugins()
    assert count >= 1
    for name, module in loader.loaded_plugins.items():
        assert hasattr(module, "METADATA")
        assert hasattr(module, "run")
        assert inspect.iscoroutinefunction(module.run)


