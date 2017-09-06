import sys
import config

if sys.version_info[0] > 2:
    LOCAL_PYEXECDIR = config.PY3EXECDIR
    LOCAL_PYDIR = config.PY3DIR
else:
    LOCAL_PYEXECDIR = config.PY2EXECDIR
    LOCAL_PYDIR = config.PY2DIR

for path in [LOCAL_PYEXECDIR, LOCAL_PYDIR]:
    if path not in sys.path:
        sys.path.insert(0, path)
