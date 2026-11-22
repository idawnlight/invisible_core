"""Python package version, independent of the bundled engine release."""

__version__ = "160.81.0"

# Retained for callers importing the historical constant.
CORE_REVISION = int(__version__.split(".")[1])
