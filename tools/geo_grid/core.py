#!/usr/bin/env python3
"""
geo_grid.core – Core geographic grid data structures.

A GeoGrid divides a rectangular bounding box (lat/lon) into a uniform
grid of cells.  Each GridCell carries optional metadata that analysis
layers can populate (e.g. signal quality, anomaly score).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterator, Optional


@dataclass(frozen=True)
class BoundingBox:
    """Axis-aligned bounding box defined by decimal-degree coordinates."""

    lat_min: float  # southern edge (degrees)
    lat_max: float  # northern edge (degrees)
    lon_min: float  # western edge (degrees)
    lon_max: float  # eastern edge (degrees)

    def __post_init__(self) -> None:
        if not (-90.0 <= self.lat_min <= 90.0):
            raise ValueError(f"lat_min out of range: {self.lat_min}")
        if not (-90.0 <= self.lat_max <= 90.0):
            raise ValueError(f"lat_max out of range: {self.lat_max}")
        if self.lat_min >= self.lat_max:
            raise ValueError("lat_min must be less than lat_max")
        if not (-180.0 <= self.lon_min <= 180.0):
            raise ValueError(f"lon_min out of range: {self.lon_min}")
        if not (-180.0 <= self.lon_max <= 180.0):
            raise ValueError(f"lon_max out of range: {self.lon_max}")
        if self.lon_min >= self.lon_max:
            raise ValueError("lon_min must be less than lon_max")

    @property
    def lat_span(self) -> float:
        """Total latitude span in degrees."""
        return self.lat_max - self.lat_min

    @property
    def lon_span(self) -> float:
        """Total longitude span in degrees."""
        return self.lon_max - self.lon_min

    @property
    def center_lat(self) -> float:
        """Center latitude of the bounding box."""
        return (self.lat_min + self.lat_max) / 2.0

    @property
    def center_lon(self) -> float:
        """Center longitude of the bounding box."""
        return (self.lon_min + self.lon_max) / 2.0

    def contains(self, lat: float, lon: float) -> bool:
        """Return True if the point (lat, lon) is inside this box."""
        return (
            self.lat_min <= lat <= self.lat_max
            and self.lon_min <= lon <= self.lon_max
        )


@dataclass
class GridCell:
    """
    A single rectangular cell within a GeoGrid.

    Attributes
    ----------
    row : int
        Zero-based row index (south → north).
    col : int
        Zero-based column index (west → east).
    bounds : BoundingBox
        The lat/lon extent of this cell.
    value : float or None
        Scalar analysis value assigned by an analysis layer.
    metadata : dict
        Arbitrary key/value metadata for additional layers.
    """

    row: int
    col: int
    bounds: BoundingBox
    value: Optional[float] = None
    metadata: dict = field(default_factory=dict)

    @property
    def center_lat(self) -> float:
        """Center latitude of the cell."""
        return self.bounds.center_lat

    @property
    def center_lon(self) -> float:
        """Center longitude of the cell."""
        return self.bounds.center_lon


class GeoGrid:
    """
    A uniform rectangular grid over a geographic bounding box.

    Parameters
    ----------
    bounds : BoundingBox
        The geographic extent of the grid.
    rows : int
        Number of rows (north–south divisions).  Must be >= 1.
    cols : int
        Number of columns (west–east divisions).  Must be >= 1.
    """

    def __init__(self, bounds: BoundingBox, rows: int, cols: int) -> None:
        if rows < 1:
            raise ValueError(f"rows must be >= 1, got {rows}")
        if cols < 1:
            raise ValueError(f"cols must be >= 1, got {cols}")

        self.bounds = bounds
        self.rows = rows
        self.cols = cols

        cell_lat = bounds.lat_span / rows
        cell_lon = bounds.lon_span / cols

        self._cells: list[list[GridCell]] = []
        for r in range(rows):
            row_cells: list[GridCell] = []
            for c in range(cols):
                cell_bounds = BoundingBox(
                    lat_min=bounds.lat_min + r * cell_lat,
                    lat_max=bounds.lat_min + (r + 1) * cell_lat,
                    lon_min=bounds.lon_min + c * cell_lon,
                    lon_max=bounds.lon_min + (c + 1) * cell_lon,
                )
                row_cells.append(GridCell(row=r, col=c, bounds=cell_bounds))
            self._cells.append(row_cells)

    # ------------------------------------------------------------------
    # Cell access helpers
    # ------------------------------------------------------------------

    def cell(self, row: int, col: int) -> GridCell:
        """Return the cell at (row, col)."""
        if not (0 <= row < self.rows and 0 <= col < self.cols):
            raise IndexError(
                f"({row}, {col}) out of bounds for grid "
                f"{self.rows}x{self.cols}"
            )
        return self._cells[row][col]

    def cells(self) -> Iterator[GridCell]:
        """Iterate over every cell in row-major order."""
        for row in self._cells:
            yield from row

    def cell_at(self, lat: float, lon: float) -> Optional[GridCell]:
        """Return the cell that contains (lat, lon), or None if outside."""
        if not self.bounds.contains(lat, lon):
            return None
        cell_lat = self.bounds.lat_span / self.rows
        cell_lon = self.bounds.lon_span / self.cols
        # Clamp to avoid floating-point overshoot at the edge
        r = min(
            int((lat - self.bounds.lat_min) / cell_lat), self.rows - 1
        )
        c = min(
            int((lon - self.bounds.lon_min) / cell_lon), self.cols - 1
        )
        return self._cells[r][c]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @property
    def cell_count(self) -> int:
        """Total number of cells in the grid."""
        return self.rows * self.cols

    @property
    def cell_lat_size(self) -> float:
        """Height of each cell in degrees."""
        return self.bounds.lat_span / self.rows

    @property
    def cell_lon_size(self) -> float:
        """Width of each cell in degrees."""
        return self.bounds.lon_span / self.cols

    def haversine_km(self) -> tuple[float, float]:
        """
        Return approximate (cell_height_km, cell_width_km) using the
        haversine formula evaluated at the grid centre latitude.
        """
        R = 6371.0  # Earth radius in km (mean radius, IAU 2015)
        lat_rad = math.radians(self.bounds.center_lat)
        cell_height_km = (math.pi / 180.0) * R * self.cell_lat_size
        cell_width_km = (
            (math.pi / 180.0) * R * self.cell_lon_size * math.cos(lat_rad)
        )
        return cell_height_km, cell_width_km

    def reset_values(self) -> None:
        """Clear all cell values and metadata."""
        for cell in self.cells():
            cell.value = None
            cell.metadata.clear()

    def values_2d(self) -> list[list[Optional[float]]]:
        """Return a 2-D list of cell values (rows × cols)."""
        return [[c.value for c in row] for row in self._cells]

    def __repr__(self) -> str:
        return (
            f"GeoGrid(bounds={self.bounds}, rows={self.rows}, "
            f"cols={self.cols})"
        )
