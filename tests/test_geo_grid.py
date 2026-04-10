#!/usr/bin/env python3
"""
tests/test_geo_grid.py – Unit tests for the geo_grid package.

Tests cover:
  * BoundingBox validation
  * GeoGrid construction, cell access, iteration
  * Analysis layers (headless – no GUI)
  * GridAnalyzer composite run
  * Headless CLI mode of geo_grid_explorer
"""

from __future__ import annotations

import math
import os
import sys

import pytest

# Ensure the tools directory is on the path before importing
_TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_TOOLS_DIR))

from geo_grid.core import BoundingBox, GeoGrid, GridCell
from geo_grid.analysis import (
    AnomalyLayer,
    DensityLayer,
    GridAnalyzer,
    HistoricalLayer,
    LayerType,
    SignalLayer,
)


# ===========================================================================
# BoundingBox tests
# ===========================================================================


class TestBoundingBox:
    def test_valid_construction(self) -> None:
        bb = BoundingBox(lat_min=10.0, lat_max=20.0, lon_min=-10.0, lon_max=0.0)
        assert bb.lat_min == 10.0
        assert bb.lat_max == 20.0

    def test_lat_span(self) -> None:
        bb = BoundingBox(lat_min=10.0, lat_max=20.0, lon_min=0.0, lon_max=5.0)
        assert bb.lat_span == pytest.approx(10.0)

    def test_lon_span(self) -> None:
        bb = BoundingBox(lat_min=0.0, lat_max=1.0, lon_min=-5.0, lon_max=5.0)
        assert bb.lon_span == pytest.approx(10.0)

    def test_center(self) -> None:
        bb = BoundingBox(lat_min=10.0, lat_max=20.0, lon_min=30.0, lon_max=50.0)
        assert bb.center_lat == pytest.approx(15.0)
        assert bb.center_lon == pytest.approx(40.0)

    def test_contains_inside(self) -> None:
        bb = BoundingBox(lat_min=0.0, lat_max=10.0, lon_min=0.0, lon_max=10.0)
        assert bb.contains(5.0, 5.0) is True

    def test_contains_outside(self) -> None:
        bb = BoundingBox(lat_min=0.0, lat_max=10.0, lon_min=0.0, lon_max=10.0)
        assert bb.contains(15.0, 5.0) is False

    def test_lat_min_ge_lat_max_raises(self) -> None:
        with pytest.raises(ValueError, match="lat_min must be less"):
            BoundingBox(lat_min=20.0, lat_max=10.0, lon_min=0.0, lon_max=1.0)

    def test_lon_min_ge_lon_max_raises(self) -> None:
        with pytest.raises(ValueError, match="lon_min must be less"):
            BoundingBox(lat_min=0.0, lat_max=1.0, lon_min=5.0, lon_max=5.0)

    def test_lat_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="lat_min out of range"):
            BoundingBox(lat_min=-100.0, lat_max=10.0, lon_min=0.0, lon_max=1.0)

    def test_lon_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="lon_max out of range"):
            BoundingBox(lat_min=0.0, lat_max=1.0, lon_min=0.0, lon_max=200.0)


# ===========================================================================
# GeoGrid tests
# ===========================================================================


class TestGeoGrid:
    _BB = BoundingBox(lat_min=40.0, lat_max=41.0, lon_min=-74.0, lon_max=-73.0)

    def _grid(self, rows: int = 5, cols: int = 5) -> GeoGrid:
        return GeoGrid(self._BB, rows=rows, cols=cols)

    def test_cell_count(self) -> None:
        g = self._grid(5, 5)
        assert g.cell_count == 25

    def test_cell_access(self) -> None:
        g = self._grid(4, 4)
        cell = g.cell(0, 0)
        assert isinstance(cell, GridCell)

    def test_cell_out_of_bounds(self) -> None:
        g = self._grid(3, 3)
        with pytest.raises(IndexError):
            g.cell(10, 0)

    def test_cells_iterator_count(self) -> None:
        g = self._grid(6, 7)
        assert sum(1 for _ in g.cells()) == 42

    def test_cell_at_center(self) -> None:
        g = self._grid(10, 10)
        cell = g.cell_at(40.5, -73.5)
        assert cell is not None

    def test_cell_at_outside_returns_none(self) -> None:
        g = self._grid()
        assert g.cell_at(0.0, 0.0) is None

    def test_cell_sizes(self) -> None:
        g = self._grid(10, 5)
        assert g.cell_lat_size == pytest.approx(0.1)
        assert g.cell_lon_size == pytest.approx(0.2)

    def test_haversine_km_positive(self) -> None:
        g = self._grid(10, 10)
        h, w = g.haversine_km()
        assert h > 0 and w > 0

    def test_values_2d_shape(self) -> None:
        g = self._grid(4, 3)
        v = g.values_2d()
        assert len(v) == 4
        assert all(len(row) == 3 for row in v)

    def test_reset_values(self) -> None:
        g = self._grid(3, 3)
        for c in g.cells():
            c.value = 1.0
        g.reset_values()
        assert all(c.value is None for c in g.cells())

    def test_rows_lt_1_raises(self) -> None:
        with pytest.raises(ValueError, match="rows must be"):
            GeoGrid(self._BB, rows=0, cols=5)

    def test_cols_lt_1_raises(self) -> None:
        with pytest.raises(ValueError, match="cols must be"):
            GeoGrid(self._BB, rows=5, cols=0)


# ===========================================================================
# Analysis layer tests
# ===========================================================================

_BB5 = BoundingBox(lat_min=40.0, lat_max=41.0, lon_min=-74.0, lon_max=-73.0)


def _fresh_grid(rows: int = 5, cols: int = 5) -> GeoGrid:
    return GeoGrid(_BB5, rows=rows, cols=cols)


class TestSignalLayer:
    def test_all_cells_get_value(self) -> None:
        g = _fresh_grid()
        SignalLayer().compute(g)
        for cell in g.cells():
            assert LayerType.SIGNAL.name in cell.metadata

    def test_values_in_range(self) -> None:
        g = _fresh_grid(10, 10)
        SignalLayer().compute(g)
        for cell in g.cells():
            v = cell.metadata[LayerType.SIGNAL.name]
            assert 0.0 <= v <= 1.0, f"Signal out of range: {v}"


class TestDensityLayer:
    def test_all_cells_get_value(self) -> None:
        g = _fresh_grid()
        DensityLayer().compute(g)
        for cell in g.cells():
            assert LayerType.DENSITY.name in cell.metadata

    def test_values_in_range(self) -> None:
        g = _fresh_grid(10, 10)
        DensityLayer().compute(g)
        for cell in g.cells():
            v = cell.metadata[LayerType.DENSITY.name]
            assert 0.0 <= v <= 1.0, f"Density out of range: {v}"


class TestHistoricalLayer:
    def test_fallback_without_prior_layers(self) -> None:
        g = _fresh_grid()
        HistoricalLayer().compute(g)
        for cell in g.cells():
            assert LayerType.HISTORICAL.name in cell.metadata

    def test_uses_signal_and_density_when_available(self) -> None:
        g = _fresh_grid()
        SignalLayer().compute(g)
        DensityLayer().compute(g)
        HistoricalLayer().compute(g)
        for cell in g.cells():
            v = cell.metadata[LayerType.HISTORICAL.name]
            assert 0.0 <= v <= 1.0


class TestAnomalyLayer:
    def test_requires_numpy_available(self) -> None:
        import numpy  # noqa: F401 – just verify it is importable

    def test_anomaly_values_in_range(self) -> None:
        g = _fresh_grid(8, 8)
        SignalLayer().compute(g)
        DensityLayer().compute(g)
        HistoricalLayer().compute(g)
        AnomalyLayer().compute(g)
        for cell in g.cells():
            v = cell.metadata[LayerType.ANOMALY.name]
            assert 0.0 <= v <= 1.0


# ===========================================================================
# GridAnalyzer tests
# ===========================================================================


class TestGridAnalyzer:
    def test_run_populates_all_values(self) -> None:
        g = _fresh_grid(6, 6)
        GridAnalyzer().run(g)
        assert all(c.value is not None for c in g.cells())

    def test_composite_in_range(self) -> None:
        g = _fresh_grid(10, 10)
        GridAnalyzer().run(g)
        for cell in g.cells():
            assert cell.value is not None
            assert 0.0 <= cell.value <= 1.0

    def test_summary_keys(self) -> None:
        g = _fresh_grid()
        analyzer = GridAnalyzer()
        analyzer.run(g)
        s = analyzer.summary(g)
        assert "min" in s
        assert "max" in s
        assert "mean" in s
        assert "count" in s
        assert s["count"] == g.cell_count

    def test_top_anomaly_cells_count(self) -> None:
        g = _fresh_grid(5, 5)
        analyzer = GridAnalyzer()
        analyzer.run(g)
        s = analyzer.summary(g)
        assert len(s["top_anomaly_cells"]) <= 5

    def test_deterministic_with_same_seed(self) -> None:
        bb = BoundingBox(40.0, 41.0, -74.0, -73.0)
        g1 = GeoGrid(bb, 4, 4)
        g2 = GeoGrid(bb, 4, 4)
        GridAnalyzer(seed=42).run(g1)
        GridAnalyzer(seed=42).run(g2)
        v1 = [c.value for c in g1.cells()]
        v2 = [c.value for c in g2.cells()]
        assert v1 == v2

    def test_different_seeds_differ(self) -> None:
        bb = BoundingBox(40.0, 41.0, -74.0, -73.0)
        g1 = GeoGrid(bb, 4, 4)
        g2 = GeoGrid(bb, 4, 4)
        GridAnalyzer(seed=1).run(g1)
        GridAnalyzer(seed=2).run(g2)
        v1 = [c.value for c in g1.cells()]
        v2 = [c.value for c in g2.cells()]
        # Very unlikely to be identical with different seeds
        assert v1 != v2


# ===========================================================================
# Headless explorer tests
# ===========================================================================


class TestHeadlessExplorer:
    """Test the CLI/headless entry-point of geo_grid_explorer."""

    def test_run_headless_produces_summary(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setenv("GEO_GRID_HEADLESS", "1")
        import importlib
        import importlib.util

        # Ensure headless flag is seen at import time
        import matplotlib

        matplotlib.use("Agg")

        # Import the explorer module from the tools directory
        explorer_path = os.path.join(
            os.path.dirname(__file__), "..", "tools", "geo_grid_explorer.py"
        )
        spec = importlib.util.spec_from_file_location(
            "geo_grid_explorer", explorer_path
        )
        explorer = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(explorer)  # type: ignore[union-attr]

        output = tmp_path / "test_grid.png"
        args = explorer._build_parser().parse_args(
            [
                "--headless",
                "--rows", "5",
                "--cols", "5",
                "--lat-min", "40.0",
                "--lat-max", "41.0",
                "--lon-min", "-74.0",
                "--lon-max", "-73.0",
                "--output", str(output),
            ]
        )
        explorer.run_headless(args)
        assert output.exists()

    def test_bounding_box_passed_to_grid(self) -> None:
        bb = BoundingBox(51.4, 51.6, -0.2, 0.0)
        g = GeoGrid(bb, 5, 5)
        assert g.bounds == bb
