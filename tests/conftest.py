import os
import sys
import types

# Ensure project root is in sys.path so 'import src...' always resolves
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Ensure local writable matplotlib config dir
mpl_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".matplotlib"))
os.makedirs(mpl_dir, exist_ok=True)
os.environ["MPLCONFIGDIR"] = mpl_dir

# Pure-python fallback for ormsgpack during pytest execution
if "ormsgpack" not in sys.modules:
    try:
        import ormsgpack
    except ImportError:
        import msgpack
        mod = types.ModuleType("ormsgpack")
        mod.MsgpackEncodeError = Exception
        mod.Ext = getattr(msgpack, "ExtType", None)
        mod.OPT_NON_STR_KEYS = 1
        mod.OPT_PASSTHROUGH_DATACLASS = 2
        mod.OPT_PASSTHROUGH_DATETIME = 4
        mod.OPT_PASSTHROUGH_ENUM = 8
        mod.OPT_PASSTHROUGH_UUID = 16
        mod.OPT_REPLACE_SURROGATES = 32
        mod.packb = lambda obj, *args, **kwargs: msgpack.packb(obj, default=str)
        mod.unpackb = lambda obj, *args, **kwargs: msgpack.unpackb(obj)
        sys.modules["ormsgpack"] = mod