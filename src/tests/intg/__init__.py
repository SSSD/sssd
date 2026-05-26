import sys
import config

LOCAL_PYEXECDIR = config.PY3EXECDIR
LOCAL_PYDIR = config.PY3DIR

for path in [LOCAL_PYEXECDIR, LOCAL_PYDIR]:
    if path not in sys.path:
        sys.path.insert(0, path)
