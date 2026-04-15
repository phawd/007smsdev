"""pytest configuration for the SMS Test test suite."""

import os

# Ensure GUI-dependent code runs headlessly during testing so that
# CI environments without a display server still work.
os.environ.setdefault("GEO_GRID_HEADLESS", "1")
