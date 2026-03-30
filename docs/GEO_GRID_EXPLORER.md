# Geographic Grid Explorer – User Guide

The **Geographic Grid Explorer** is a graphical Python desktop tool included
with SMS Test.  It lets you define a rectangular geographic area by
latitude/longitude bounds, divide it into a configurable grid, and instantly
see multi-layer AI-driven analysis rendered as an interactive heatmap.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Launch the GUI
python tools/geo_grid_explorer.py

# Run without a display (CI / server)
python tools/geo_grid_explorer.py --headless \
    --rows 20 --cols 20 \
    --lat-min 40.6 --lat-max 40.8 \
    --lon-min -74.05 --lon-max -73.85 \
    --output my_grid.png
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Lat/Lon grid input** | Define the area of interest with decimal-degree bounding box coordinates |
| **Configurable resolution** | Choose any grid size from 2 × 2 up to 200 × 200 cells |
| **Layer selector** | Switch between Composite, Signal Strength, Population Density, Historical Delivery Rate, and Anomaly views |
| **Background analysis** | Analysis runs in a background thread; the UI stays responsive |
| **Save image** | Export the current heatmap as PNG, PDF, or SVG |
| **Headless / CLI mode** | Run from a terminal or CI pipeline without a display |

---

## Analysis Layers

The tool uses four analysis layers that can be independently inspected:

### 1. Signal Strength
Models cellular signal coverage using synthetic tower positions.  Values
near 1.0 indicate strong coverage; values near 0.0 indicate dead zones.

### 2. Population Density
A proxy density estimate derived from the geographic position of each
cell.  Urban areas (near integer lat/lon multiples) score higher.

### 3. Historical Delivery Rate
Simulates historical SMS delivery success rates, incorporating both
signal and density data when available.  In a production deployment this
layer would consume real delivery logs.

### 4. Anomaly Score
Detects cells that deviate significantly from the neighbourhood average
across all layers.  High anomaly scores (> 0.6) highlight cells worth
investigating for network or coverage issues.

### Composite
A weighted average of all layers:

```
composite = 0.35 × signal + 0.25 × density + 0.25 × historical + 0.15 × anomaly
```

---

## Extending Analysis Layers

Add a custom layer by subclassing `AnalysisLayer`:

```python
from tools.geo_grid.analysis import AnalysisLayer, LayerType
from tools.geo_grid.core import GeoGrid


class MyCustomLayer(AnalysisLayer):
    layer_type = LayerType.SIGNAL  # reuse any LayerType or add your own

    def compute(self, grid: GeoGrid, rng=None) -> None:
        for cell in grid.cells():
            # Write your computed value to cell.metadata
            cell.metadata["MY_LAYER"] = some_function(cell.center_lat, cell.center_lon)


# Pass to GridAnalyzer
from tools.geo_grid.analysis import GridAnalyzer, SignalLayer, DensityLayer

analyzer = GridAnalyzer(layers=(SignalLayer, DensityLayer, MyCustomLayer))
analyzer.run(grid)
```

---

## Building a Standalone Executable

Use [PyInstaller](https://pyinstaller.org) to package the app as a
single-folder executable:

```bash
pip install pyinstaller
pyinstaller geo_grid_explorer.spec
```

The output is placed in `dist/geo_grid_explorer/`.  On Windows this
produces `geo_grid_explorer.exe`; on macOS/Linux it produces
`geo_grid_explorer`.

---

## Running Tests

```bash
pip install pytest numpy matplotlib
pytest tests/test_geo_grid.py -v
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `PyQt5` | Desktop GUI framework |
| `matplotlib` | Heatmap rendering |
| `numpy` | Numerical analysis |
| `requests` | (optional) fetch external geodata |
| `pyinstaller` | Standalone executable packaging |

Install all dependencies at once:

```bash
pip install -r requirements.txt
```
