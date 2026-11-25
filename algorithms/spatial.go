package algorithms

import "math"

const spatialBias = 32768

// PackCellKey empacota coordenadas de célula (cx, cy, cz) e routing bucket (15-bit) em uma chave uint64 O(1).
func PackCellKey(cx, cy, cz int, bucket uint16) uint64 {
	b := uint64(bucket & 0x7FFF)
	return (b << 48) | (uint64(cx&0xFFFF) << 32) | (uint64(cy&0xFFFF) << 16) | uint64(cz&0xFFFF)
}

// SpatialEntity representa uma entidade indexada no SpatialGrid 2D/3D.
type SpatialEntity[T any] struct {
	ID        string
	X, Y, Z   float64
	Bucket    uint16
	CellKey   uint64
	CellIndex int
	Payload   T
}

// SpatialGrid implementa indexação espacial O(1) por Bit-Packed 64-bit Spatial Hash Grid 2D/3D.
type SpatialGrid[T any] struct {
	cellSize    float64
	invCellSize float64
	cells       map[uint64][]*SpatialEntity[T]
	entities    map[string]*SpatialEntity[T]
}

func NewSpatialGrid[T any](cellSize float64) *SpatialGrid[T] {
	if cellSize <= 0 {
		cellSize = 50.0
	}
	return &SpatialGrid[T]{
		cellSize:    cellSize,
		invCellSize: 1.0 / cellSize,
		cells:       make(map[uint64][]*SpatialEntity[T]),
		entities:    make(map[string]*SpatialEntity[T]),
	}
}

func (sg *SpatialGrid[T]) coordToCell(x, y, z float64, bucket uint16) uint64 {
	cx := int(math.Floor(x*sg.invCellSize)) + spatialBias
	cy := int(math.Floor(y*sg.invCellSize)) + spatialBias
	cz := int(math.Floor(z*sg.invCellSize)) + spatialBias
	return PackCellKey(cx, cy, cz, bucket)
}

func (sg *SpatialGrid[T]) removeFromCell(ent *SpatialEntity[T]) {
	cell := sg.cells[ent.CellKey]
	n := len(cell)
	if n == 0 {
		return
	}
	idx := ent.CellIndex
	last := cell[n-1]
	if idx < n-1 && last != nil {
		cell[idx] = last
		last.CellIndex = idx
	}
	if n == 1 {
		delete(sg.cells, ent.CellKey)
	} else {
		sg.cells[ent.CellKey] = cell[:n-1]
	}
}

func (sg *SpatialGrid[T]) Insert(id string, x, y, z float64, bucket uint16, payload T) bool {
	if _, exists := sg.entities[id]; exists {
		return sg.Update(id, x, y, z, bucket)
	}
	key := sg.coordToCell(x, y, z, bucket)
	cell := sg.cells[key]
	ent := &SpatialEntity[T]{
		ID:        id,
		X:         x,
		Y:         y,
		Z:         z,
		Bucket:    bucket,
		CellKey:   key,
		CellIndex: len(cell),
		Payload:   payload,
	}
	sg.cells[key] = append(cell, ent)
	sg.entities[id] = ent
	return true
}

func (sg *SpatialGrid[T]) Update(id string, x, y, z float64, bucket uint16) bool {
	ent, exists := sg.entities[id]
	if !exists {
		return false
	}
	newKey := sg.coordToCell(x, y, z, bucket)
	ent.X, ent.Y, ent.Z, ent.Bucket = x, y, z, bucket
	if newKey != ent.CellKey {
		sg.removeFromCell(ent)
		cell := sg.cells[newKey]
		ent.CellKey = newKey
		ent.CellIndex = len(cell)
		sg.cells[newKey] = append(cell, ent)
	}
	return true
}

func (sg *SpatialGrid[T]) Remove(id string) bool {
	ent, exists := sg.entities[id]
	if !exists {
		return false
	}
	sg.removeFromCell(ent)
	delete(sg.entities, id)
	return true
}

func (sg *SpatialGrid[T]) QueryRadius(x, y, z, radius float64, bucket uint16) []*SpatialEntity[T] {
	var results []*SpatialEntity[T]
	rSq := radius * radius
	inv := sg.invCellSize
	bShift := uint64(bucket&0x7FFF) << 48

	minCx := int(math.Floor((x-radius)*inv)) + spatialBias
	maxCx := int(math.Floor((x+radius)*inv)) + spatialBias
	minCy := int(math.Floor((y-radius)*inv)) + spatialBias
	maxCy := int(math.Floor((y+radius)*inv)) + spatialBias
	minCz := int(math.Floor((z-radius)*inv)) + spatialBias
	maxCz := int(math.Floor((z+radius)*inv)) + spatialBias

	for cx := minCx; cx <= maxCx; cx++ {
		cxBits := bShift | (uint64(cx&0xFFFF) << 32)
		for cy := minCy; cy <= maxCy; cy++ {
			cyBits := cxBits | (uint64(cy&0xFFFF) << 16)
			for cz := minCz; cz <= maxCz; cz++ {
				cell := sg.cells[cyBits|uint64(cz&0xFFFF)]
				for _, ent := range cell {
					dx, dy, dz := ent.X-x, ent.Y-y, ent.Z-z
					if dx*dx+dy*dy+dz*dz <= rSq {
						results = append(results, ent)
					}
				}
			}
		}
	}
	return results
}

// PolygonZone implementa um polígono 2.5D com pré-filtro AABB e Ray-Casting.
type PolygonZone struct {
	MinZ, MaxZ float64
	MinX, MaxX float64
	MinY, MaxY float64
	vx, vy     []float64
}

func NewPolygon(minZ, maxZ float64, points []float64) *PolygonZone {
	if len(points) < 6 || len(points)%2 != 0 {
		panic("algorithms.NewPolygon: poligono exige pelo menos 3 pares (x, y)")
	}
	minX, maxX := math.Inf(1), math.Inf(-1)
	minY, maxY := math.Inf(1), math.Inf(-1)
	nVerts := len(points) / 2
	vx := make([]float64, nVerts)
	vy := make([]float64, nVerts)
	for i := 0; i < nVerts; i++ {
		px, py := points[i*2], points[i*2+1]
		vx[i], vy[i] = px, py
		if px < minX {
			minX = px
		}
		if px > maxX {
			maxX = px
		}
		if py < minY {
			minY = py
		}
		if py > maxY {
			maxY = py
		}
	}
	return &PolygonZone{
		MinZ: minZ, MaxZ: maxZ,
		MinX: minX, MaxX: maxX,
		MinY: minY, MaxY: maxY,
		vx: vx, vy: vy,
	}
}

func (pz *PolygonZone) Contains(x, y, z float64) bool {
	if z < pz.MinZ || z > pz.MaxZ || x < pz.MinX || x > pz.MaxX || y < pz.MinY || y > pz.MaxY {
		return false
	}
	inside := false
	n := len(pz.vx)
	j := n - 1
	for i := 0; i < n; i++ {
		xi, yi := pz.vx[i], pz.vy[i]
		xj, yj := pz.vx[j], pz.vy[j]
		if ((yi > y) != (yj > y)) && (x < (xj-xi)*(y-yi)/(yj-yi)+xi) {
			inside = !inside
		}
		j = i
	}
	return inside
}
