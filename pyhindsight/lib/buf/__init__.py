# Package marker for buf-generated protobuf modules.
#
# The generated code imports `components.*` as a top-level package. When
# importing via `pyhindsight.lib.buf`, provide an alias so those imports
# resolve without requiring a separate top-level `components` package.
import sys as _sys

from . import components as _components

_sys.modules.setdefault("components", _components)
