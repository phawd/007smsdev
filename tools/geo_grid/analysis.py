#!/usr/bin/env python3
"""
geo_grid.analysis – Layered analysis engine for GeoGrid.

Each AnalysisLayer produces a scalar value for every GridCell.  The
GridAnalyzer orchestrates multiple layers and merges their outputs into
a single composite score, mimicking the kind of multi-source AI
reasoning described in the project requirements.

Layers included (all run without external data for offline/CI use):
  * SignalLayer   – simulated cellular/SMS signal heat-map
  * DensityLayer  – population-density proxy from lat/lon heuristics
  * HistoricalLayer – historical SMS delivery pattern simulation
  * AnomalyLayer  – anomaly score derived from the other layers
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Optional

import numpy as np  # type: ignore[import]

from .core import GeoGrid, GridCell


class LayerType(Enum):
    SIGNAL = auto()
    DENSITY = auto()
    HISTORICAL = auto()
    ANOMALY = auto()
    COMPOSITE = auto()


class AnalysisLayer(ABC):
    """Abstract base class for a grid analysis layer."""

    layer_type: LayerType

    @abstractmethod
    def compute(self, grid: GeoGrid, rng: Optional[random.Random] = None) -> None:
        """
        Populate each cell's `value` and write layer-specific keys into
        `cell.metadata[self.layer_type.name]`.
        """


class SignalLayer(AnalysisLayer):
    """
    Simulates cellular signal strength (0.0 – 1.0) based on distance
    from synthetic tower positions placed near the grid centre and
    corners.
    """

    layer_type = LayerType.SIGNAL

    def compute(self, grid: GeoGrid, rng: Optional[random.Random] = None) -> None:
        rng = rng or random.Random(42)
        b = grid.bounds

        # Place towers at grid centre and four quadrant centres
        tower_positions = [
            (b.center_lat, b.center_lon),
            (b.lat_min + b.lat_span * 0.25, b.lon_min + b.lon_span * 0.25),
            (b.lat_min + b.lat_span * 0.75, b.lon_min + b.lon_span * 0.25),
            (b.lat_min + b.lat_span * 0.25, b.lon_min + b.lon_span * 0.75),
            (b.lat_min + b.lat_span * 0.75, b.lon_min + b.lon_span * 0.75),
        ]

        max_dist = math.sqrt(b.lat_span**2 + b.lon_span**2) / 2.0

        for cell in grid.cells():
            # Nearest-tower distance as a proxy for signal strength
            min_dist = min(
                math.sqrt(
                    (cell.center_lat - tlat) ** 2
                    + (cell.center_lon - tlon) ** 2
                )
                for tlat, tlon in tower_positions
            )
            # Normalise: closer = stronger; add small noise
            signal = max(0.0, 1.0 - (min_dist / max_dist))
            signal = min(1.0, signal + rng.gauss(0.0, 0.03))
            cell.metadata[LayerType.SIGNAL.name] = round(signal, 4)


class DensityLayer(AnalysisLayer):
    """
    Estimates relative population density (0.0 – 1.0) using a simple
    heuristic: urban centres tend to cluster near round-number lat/lon
    values and away from the poles.
    """

    layer_type = LayerType.DENSITY

    def compute(self, grid: GeoGrid, rng: Optional[random.Random] = None) -> None:
        rng = rng or random.Random(7)

        for cell in grid.cells():
            lat_factor = math.cos(math.radians(abs(cell.center_lat)))
            # Prefer cells near integer lat/lon multiples (urban proxy)
            lat_frac = 1.0 - abs(round(cell.center_lat) - cell.center_lat)
            lon_frac = 1.0 - abs(round(cell.center_lon) - cell.center_lon)
            density = lat_factor * (lat_frac + lon_frac) / 2.0
            density = min(1.0, max(0.0, density + rng.gauss(0.0, 0.05)))
            cell.metadata[LayerType.DENSITY.name] = round(density, 4)


class HistoricalLayer(AnalysisLayer):
    """
    Synthesises a historical SMS delivery-rate pattern (0.0 – 1.0).

    In a real deployment this layer would consume logged delivery
    statistics.  Here it derives values from the SIGNAL and DENSITY
    layers (if already computed) or falls back to random noise.
    """

    layer_type = LayerType.HISTORICAL

    def compute(self, grid: GeoGrid, rng: Optional[random.Random] = None) -> None:
        rng = rng or random.Random(99)
        signal_key = LayerType.SIGNAL.name
        density_key = LayerType.DENSITY.name

        for cell in grid.cells():
            sig = cell.metadata.get(signal_key)
            den = cell.metadata.get(density_key)
            if sig is not None and den is not None:
                base = 0.6 * sig + 0.4 * den
            else:
                base = rng.uniform(0.3, 0.9)
            hist = min(1.0, max(0.0, base + rng.gauss(0.0, 0.04)))
            cell.metadata[LayerType.HISTORICAL.name] = round(hist, 4)


class AnomalyLayer(AnalysisLayer):
    """
    Detects anomalous cells where the composite picture diverges from
    the local neighbourhood average.  High anomaly score (> 0.6)
    indicates a cell worth investigating.
    """

    layer_type = LayerType.ANOMALY

    def compute(self, grid: GeoGrid, rng: Optional[random.Random] = None) -> None:
        rng = rng or random.Random(13)
        signal_key = LayerType.SIGNAL.name
        density_key = LayerType.DENSITY.name
        hist_key = LayerType.HISTORICAL.name

        # Collect composite scores for all cells
        scores: list[list[float]] = []
        for r in range(grid.rows):
            row_scores = []
            for c in range(grid.cols):
                cell = grid.cell(r, c)
                sig = cell.metadata.get(signal_key, 0.5)
                den = cell.metadata.get(density_key, 0.5)
                hist = cell.metadata.get(hist_key, 0.5)
                composite = (sig + den + hist) / 3.0
                row_scores.append(composite)
            scores.append(row_scores)

        arr = np.array(scores, dtype=float)
        global_mean = float(arr.mean())
        global_std = max(float(arr.std()), 1e-6)

        for r in range(grid.rows):
            for c in range(grid.cols):
                cell = grid.cell(r, c)
                z = abs(scores[r][c] - global_mean) / global_std
                # Map z-score to [0, 1] via sigmoid-like normalisation
                anomaly = 1.0 / (1.0 + math.exp(-z + 2.0))
                cell.metadata[LayerType.ANOMALY.name] = round(anomaly, 4)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class GridAnalyzer:
    """
    Orchestrates multiple AnalysisLayers over a single GeoGrid and
    produces a composite score for each cell.

    Usage
    -----
    >>> from tools.geo_grid import GeoGrid, BoundingBox, GridAnalyzer
    >>> bb = BoundingBox(lat_min=40.0, lat_max=41.0, lon_min=-74.0, lon_max=-73.0)
    >>> grid = GeoGrid(bb, rows=10, cols=10)
    >>> analyzer = GridAnalyzer()
    >>> results = analyzer.run(grid)
    """

    DEFAULT_LAYERS: tuple[type[AnalysisLayer], ...] = (
        SignalLayer,
        DensityLayer,
        HistoricalLayer,
        AnomalyLayer,
    )

    def __init__(
        self,
        layers: Optional[tuple[type[AnalysisLayer], ...]] = None,
        seed: int = 0,
    ) -> None:
        layer_classes = layers or self.DEFAULT_LAYERS
        rng = random.Random(seed)
        self._layers: list[AnalysisLayer] = [cls() for cls in layer_classes]
        self._rng = rng

    def run(self, grid: GeoGrid) -> GeoGrid:
        """
        Run all layers in sequence and write a composite `cell.value`
        (0.0 – 1.0) derived from SIGNAL, DENSITY, and HISTORICAL scores.

        Returns the same grid with values populated.
        """
        grid.reset_values()

        # Give each layer its own independent RNG seeded from the parent
        for layer in self._layers:
            child_rng = random.Random(self._rng.randint(0, 2**32))
            layer.compute(grid, child_rng)

        # Write composite value
        sig_key = LayerType.SIGNAL.name
        den_key = LayerType.DENSITY.name
        hist_key = LayerType.HISTORICAL.name
        anom_key = LayerType.ANOMALY.name

        for cell in grid.cells():
            sig = cell.metadata.get(sig_key, 0.0)
            den = cell.metadata.get(den_key, 0.0)
            hist = cell.metadata.get(hist_key, 0.0)
            anom = cell.metadata.get(anom_key, 0.0)
            # Composite weighting rationale:
            #   Signal (0.35)     – strongest predictor of SMS delivery success
            #   Density (0.25)    – higher population → more traffic, affects quality
            #   Historical (0.25) – past delivery rates are a reliable baseline
            #   Anomaly (0.15)    – surface outliers without dominating the score
            composite = 0.35 * sig + 0.25 * den + 0.25 * hist + 0.15 * anom
            cell.value = round(composite, 4)
            cell.metadata[LayerType.COMPOSITE.name] = cell.value

        return grid

    def summary(self, grid: GeoGrid) -> dict:
        """Return descriptive statistics over cell composite values."""
        vals = [c.value for c in grid.cells() if c.value is not None]
        if not vals:
            return {}
        arr = np.array(vals)
        return {
            "count": int(arr.size),
            "min": float(arr.min()),
            "max": float(arr.max()),
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "top_anomaly_cells": self._top_anomaly_cells(grid, n=5),
        }

    @staticmethod
    def _top_anomaly_cells(grid: GeoGrid, n: int = 5) -> list[dict]:
        """Return the n cells with the highest anomaly score."""
        anom_key = LayerType.ANOMALY.name
        ranked = sorted(
            grid.cells(),
            key=lambda c: c.metadata.get(anom_key, 0.0),
            reverse=True,
        )[:n]
        return [
            {
                "row": c.row,
                "col": c.col,
                "lat": c.center_lat,
                "lon": c.center_lon,
                "anomaly": c.metadata.get(anom_key),
                "composite": c.value,
            }
            for c in ranked
        ]
