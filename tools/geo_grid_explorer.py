#!/usr/bin/env python3
"""
geo_grid_explorer.py – Graphical geographic grid explorer for SMS Test.

Allows users to define a geographic grid by lat/lon bounds or by
typing a place name, then runs multi-layer AI analysis (signal,
density, historical, anomaly) and renders the results as an
interactive heatmap using PyQt5 + Matplotlib.

Usage
-----
    python tools/geo_grid_explorer.py
    python tools/geo_grid_explorer.py --headless --rows 10 --cols 10 \
        --lat-min 40.0 --lat-max 41.0 --lon-min -74.0 --lon-max -73.0

Packaging
---------
    pyinstaller geo_grid_explorer.spec
"""

from __future__ import annotations

import argparse
import os
import sys

# ---------------------------------------------------------------------------
# Headless / CI guard – must happen before any Qt or Matplotlib import
# ---------------------------------------------------------------------------
_HEADLESS = os.environ.get("GEO_GRID_HEADLESS", "").lower() in ("1", "true", "yes")
_CLI_HEADLESS = "--headless" in sys.argv

if _HEADLESS or _CLI_HEADLESS:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import matplotlib

    matplotlib.use("Agg")

# ---------------------------------------------------------------------------
# Standard imports
# ---------------------------------------------------------------------------
import json
import math

import matplotlib.pyplot as plt  # type: ignore[import]
import numpy as np  # type: ignore[import]

# Qt / Matplotlib Qt backend – only imported when running in GUI mode
if not (_HEADLESS or _CLI_HEADLESS):
    try:
        from matplotlib.backends.backend_qt5agg import (  # type: ignore[import]
            FigureCanvasQTAgg as FigureCanvas,
        )
        from matplotlib.figure import Figure  # type: ignore[import]
    except ImportError:
        FigureCanvas = object  # type: ignore[assignment,misc]
        Figure = None  # type: ignore[assignment,misc]
else:
    FigureCanvas = object  # type: ignore[assignment,misc]
    Figure = None  # type: ignore[assignment,misc]

try:
    from PyQt5.QtCore import Qt, QThread, pyqtSignal  # type: ignore[import]
    from PyQt5.QtGui import QFont  # type: ignore[import]
    from PyQt5.QtWidgets import (  # type: ignore[import]
        QApplication,
        QComboBox,
        QDoubleSpinBox,
        QFormLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QSizePolicy,
        QSpinBox,
        QSplitter,
        QStatusBar,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    _QT_AVAILABLE = True
except ImportError:
    _QT_AVAILABLE = False

# Add the tools directory to PYTHONPATH so geo_grid can be imported both
# when running from the repo root and from within the tools/ directory.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from geo_grid import BoundingBox, GeoGrid, GridAnalyzer  # noqa: E402
from geo_grid.analysis import LayerType  # noqa: E402


# ---------------------------------------------------------------------------
# Worker – runs analysis without blocking the UI
# ---------------------------------------------------------------------------

def _run_analysis_sync(
    bounds: BoundingBox, rows: int, cols: int
) -> tuple[GeoGrid, dict]:
    """Execute grid analysis synchronously.  Used by the headless path."""
    grid = GeoGrid(bounds, rows, cols)
    analyzer = GridAnalyzer()
    analyzer.run(grid)
    return grid, analyzer.summary(grid)


if _QT_AVAILABLE:

    class AnalysisWorker(QThread):  # type: ignore[misc]
        """Run GridAnalyzer in a background thread so the UI stays responsive."""

        finished = pyqtSignal(object, dict)   # (grid, summary)
        error = pyqtSignal(str)

        def __init__(self, bounds: BoundingBox, rows: int, cols: int) -> None:
            super().__init__()
            self.bounds = bounds
            self.rows = rows
            self.cols = cols

        def run(self) -> None:
            try:
                grid, summary = _run_analysis_sync(
                    self.bounds, self.rows, self.cols
                )
                self.finished.emit(grid, summary)
            except Exception as exc:  # pragma: no cover
                self.error.emit(str(exc))



# ---------------------------------------------------------------------------
# GUI classes – only defined when PyQt5 is available
# ---------------------------------------------------------------------------

if _QT_AVAILABLE:
    from matplotlib.figure import Figure  # type: ignore[import]
    from matplotlib.backends.backend_qt5agg import (  # type: ignore[import]
        FigureCanvasQTAgg as _FigureCanvas,
    )

    class HeatmapCanvas(_FigureCanvas):
        """Renders a 2-D heatmap of grid cell values."""

        def __init__(self, parent: "QWidget | None" = None) -> None:
            self.figure = Figure(figsize=(6, 5), tight_layout=True)
            super().__init__(self.figure)
            self.setParent(parent)
            self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self.updateGeometry()
            self.ax = self.figure.add_subplot(111)

        def plot(
            self,
            grid: GeoGrid,
            layer: str = LayerType.COMPOSITE.name,
            title: str = "Grid Analysis",
        ) -> None:
            self.ax.clear()

            data = np.array(
                [
                    [
                        grid.cell(r, c).metadata.get(layer, 0.0)
                        for c in range(grid.cols)
                    ]
                    for r in range(grid.rows)
                ]
            )

            im = self.ax.imshow(
                data,
                origin="lower",
                aspect="auto",
                cmap="RdYlGn",
                vmin=0.0,
                vmax=1.0,
                extent=[
                    grid.bounds.lon_min,
                    grid.bounds.lon_max,
                    grid.bounds.lat_min,
                    grid.bounds.lat_max,
                ],
            )
            self.figure.colorbar(im, ax=self.ax, label="Score (0–1)")
            self.ax.set_title(title, fontsize=11)
            self.ax.set_xlabel("Longitude")
            self.ax.set_ylabel("Latitude")
            self.draw()

        def save(self, path: str) -> None:
            """Save current figure to a file (PNG, PDF, SVG…)."""
            self.figure.savefig(path, dpi=150)

    # -----------------------------------------------------------------------
    # Main window
    # -----------------------------------------------------------------------

    class MainWindow(QMainWindow):
        """Primary application window."""

        LAYER_CHOICES: list[tuple[str, str]] = [
            (LayerType.COMPOSITE.name, "Composite"),
            (LayerType.SIGNAL.name, "Signal Strength"),
            (LayerType.DENSITY.name, "Population Density"),
            (LayerType.HISTORICAL.name, "Historical Delivery Rate"),
            (LayerType.ANOMALY.name, "Anomaly Score"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self._grid: "GeoGrid | None" = None
            self._worker: "AnalysisWorker | None" = None
            self._build_ui()

        # ------------------------------------------------------------------
        # UI construction
        # ------------------------------------------------------------------

        def _build_ui(self) -> None:
            self.setWindowTitle("SMS Test – Geographic Grid Explorer")
            self.setMinimumSize(1000, 650)

            # ---- Central widget ----
            central = QWidget()
            self.setCentralWidget(central)
            root_layout = QHBoxLayout(central)

            splitter = QSplitter(Qt.Horizontal)
            root_layout.addWidget(splitter)

            # ---- Left panel (controls) ----
            control_panel = QWidget()
            control_layout = QVBoxLayout(control_panel)
            control_panel.setMaximumWidth(320)

            title_lbl = QLabel("Geographic Grid Explorer")
            title_font = QFont()
            title_font.setPointSize(13)
            title_font.setBold(True)
            title_lbl.setFont(title_font)
            control_layout.addWidget(title_lbl)

            # -- Bounding box group --
            bbox_group = QGroupBox("Bounding Box (decimal degrees)")
            bbox_form = QFormLayout(bbox_group)

            def _dspin(val: float, lo: float, hi: float) -> QDoubleSpinBox:
                sb = QDoubleSpinBox()
                sb.setDecimals(6)
                sb.setRange(lo, hi)
                sb.setValue(val)
                return sb

            self.lat_min_sb = _dspin(40.6, -90.0, 90.0)
            self.lat_max_sb = _dspin(40.8, -90.0, 90.0)
            self.lon_min_sb = _dspin(-74.05, -180.0, 180.0)
            self.lon_max_sb = _dspin(-73.85, -180.0, 180.0)

            bbox_form.addRow("Lat min:", self.lat_min_sb)
            bbox_form.addRow("Lat max:", self.lat_max_sb)
            bbox_form.addRow("Lon min:", self.lon_min_sb)
            bbox_form.addRow("Lon max:", self.lon_max_sb)
            control_layout.addWidget(bbox_group)

            # -- Grid size group --
            grid_group = QGroupBox("Grid Resolution")
            grid_form = QFormLayout(grid_group)

            self.rows_sb = QSpinBox()
            self.rows_sb.setRange(2, 200)
            self.rows_sb.setValue(20)

            self.cols_sb = QSpinBox()
            self.cols_sb.setRange(2, 200)
            self.cols_sb.setValue(20)

            grid_form.addRow("Rows:", self.rows_sb)
            grid_form.addRow("Cols:", self.cols_sb)
            control_layout.addWidget(grid_group)

            # -- Layer selector --
            layer_group = QGroupBox("Display Layer")
            layer_layout = QVBoxLayout(layer_group)
            self.layer_combo = QComboBox()
            for key, label in self.LAYER_CHOICES:
                self.layer_combo.addItem(label, key)
            self.layer_combo.currentIndexChanged.connect(self._refresh_plot)
            layer_layout.addWidget(self.layer_combo)
            control_layout.addWidget(layer_group)

            # -- Buttons --
            btn_layout = QHBoxLayout()
            self.run_btn = QPushButton("Analyse Grid")
            self.run_btn.setMinimumHeight(36)
            self.run_btn.clicked.connect(self._run_analysis)
            btn_layout.addWidget(self.run_btn)

            self.save_btn = QPushButton("Save Image")
            self.save_btn.setMinimumHeight(36)
            self.save_btn.clicked.connect(self._save_image)
            self.save_btn.setEnabled(False)
            btn_layout.addWidget(self.save_btn)
            control_layout.addLayout(btn_layout)

            # -- Summary box --
            summary_group = QGroupBox("Analysis Summary")
            summary_layout = QVBoxLayout(summary_group)
            self.summary_text = QTextEdit()
            self.summary_text.setReadOnly(True)
            self.summary_text.setMaximumHeight(180)
            summary_layout.addWidget(self.summary_text)
            control_layout.addWidget(summary_group)

            control_layout.addStretch()

            # ---- Right panel (heatmap) ----
            self.canvas = HeatmapCanvas()

            splitter.addWidget(control_panel)
            splitter.addWidget(self.canvas)
            splitter.setStretchFactor(0, 0)
            splitter.setStretchFactor(1, 1)

            # ---- Status bar ----
            self.setStatusBar(QStatusBar())
            self.statusBar().showMessage(
                "Ready.  Define a grid and click 'Analyse Grid'."
            )

        # ------------------------------------------------------------------
        # Slots
        # ------------------------------------------------------------------

        def _run_analysis(self) -> None:
            try:
                bounds = BoundingBox(
                    lat_min=self.lat_min_sb.value(),
                    lat_max=self.lat_max_sb.value(),
                    lon_min=self.lon_min_sb.value(),
                    lon_max=self.lon_max_sb.value(),
                )
            except ValueError as exc:
                QMessageBox.warning(self, "Invalid bounds", str(exc))
                return

            rows = self.rows_sb.value()
            cols = self.cols_sb.value()

            self.run_btn.setEnabled(False)
            self.statusBar().showMessage("Running analysis…")

            self._worker = AnalysisWorker(bounds, rows, cols)
            self._worker.finished.connect(self._on_analysis_done)
            self._worker.error.connect(self._on_analysis_error)
            self._worker.start()

        def _on_analysis_done(self, grid: "GeoGrid", summary: dict) -> None:
            self._grid = grid
            self._refresh_plot()
            self.save_btn.setEnabled(True)
            self.run_btn.setEnabled(True)
            self.statusBar().showMessage(
                f"Done.  {grid.rows}×{grid.cols} grid analysed."
            )
            self.summary_text.setPlainText(
                json.dumps(summary, indent=2, default=str)
            )

        def _on_analysis_error(self, msg: str) -> None:  # pragma: no cover
            QMessageBox.critical(self, "Analysis Error", msg)
            self.run_btn.setEnabled(True)
            self.statusBar().showMessage("Error – see dialog.")

        def _refresh_plot(self) -> None:
            if self._grid is None:
                return
            layer_key = self.layer_combo.currentData()
            label = self.layer_combo.currentText()
            self.canvas.plot(self._grid, layer=layer_key, title=label)

        def _save_image(self) -> None:
            from PyQt5.QtWidgets import QFileDialog  # type: ignore[import]

            path, _ = QFileDialog.getSaveFileName(
                self,
                "Save heatmap image",
                "grid_analysis.png",
                "Images (*.png *.pdf *.svg)",
            )
            if path:
                self.canvas.save(path)
                self.statusBar().showMessage(f"Saved to {path}")


# ---------------------------------------------------------------------------
# Headless / CLI mode
# ---------------------------------------------------------------------------

def run_headless(args: argparse.Namespace) -> None:
    """Run analysis headlessly and write a PNG to disk."""
    bounds = BoundingBox(
        lat_min=args.lat_min,
        lat_max=args.lat_max,
        lon_min=args.lon_min,
        lon_max=args.lon_max,
    )
    grid = GeoGrid(bounds, rows=args.rows, cols=args.cols)
    analyzer = GridAnalyzer()
    analyzer.run(grid)
    summary = analyzer.summary(grid)

    print(json.dumps(summary, indent=2, default=str))

    output = getattr(args, "output", "grid_analysis.png")
    if output:
        data = np.array(
            [
                [grid.cell(r, c).value or 0.0 for c in range(grid.cols)]
                for r in range(grid.rows)
            ]
        )
        fig, ax = plt.subplots(figsize=(8, 6))
        im = ax.imshow(
            data,
            origin="lower",
            aspect="auto",
            cmap="RdYlGn",
            vmin=0.0,
            vmax=1.0,
            extent=[
                bounds.lon_min, bounds.lon_max,
                bounds.lat_min, bounds.lat_max,
            ],
        )
        fig.colorbar(im, ax=ax, label="Composite Score (0–1)")
        ax.set_title("Geographic Grid Analysis – Composite")
        ax.set_xlabel("Longitude")
        ax.set_ylabel("Latitude")
        fig.tight_layout()
        fig.savefig(output, dpi=150)
        plt.close(fig)
        print(f"Saved heatmap to {output}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SMS Test – Geographic Grid Explorer"
    )
    p.add_argument("--headless", action="store_true", help="Run without GUI")
    p.add_argument("--rows", type=int, default=20, help="Grid rows")
    p.add_argument("--cols", type=int, default=20, help="Grid cols")
    p.add_argument("--lat-min", type=float, default=40.6, dest="lat_min")
    p.add_argument("--lat-max", type=float, default=40.8, dest="lat_max")
    p.add_argument("--lon-min", type=float, default=-74.05, dest="lon_min")
    p.add_argument("--lon-max", type=float, default=-73.85, dest="lon_max")
    p.add_argument(
        "--output",
        default="grid_analysis.png",
        help="Output image path (headless mode)",
    )
    return p


def main() -> None:
    args = _build_parser().parse_args()

    if args.headless or _HEADLESS:
        run_headless(args)
        return

    if not _QT_AVAILABLE:
        print(
            "PyQt5 is not installed.  Install it with:\n"
            "  pip install PyQt5\n"
            "or run in headless mode with --headless",
            file=sys.stderr,
        )
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("SMS Test – Grid Explorer")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
