sss_analyze_pythondir = $(libexecdir)/sssd

dist_sss_analyze_python_SCRIPTS = \
    sss_analyze \
    $(NULL)

pkgpythondir = $(python3dir)/sssd

dist_pkgpython_DATA = \
    __init__.py \
    source_files.py \
    source_journald.py \
    source_reader.py \
    parser.py \
    sss_analyze.py \
    util.py \
    $(NULL)

modulesdir = $(pkgpythondir)/modules
dist_modules_DATA = \
    modules/__init__.py \
    modules/request.py \
    modules/error.py \
    $(NULL)
