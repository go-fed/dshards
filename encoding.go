package dshards

import (
	"bytes"
	"fmt"

	"github.com/cjslep/syrup"
)

const (
	kManifest = "manifest"
	kRaw      = "raw"
)

// chunker are Manifest and Raw files that know how to chunk their contents into
// multiple (if necessary) datashards-compatible byte streams.
type chunker interface {
	Chunk() ([][]byte, error)
}

type manifest struct {
	urns []URN
}

func (m manifest) Chunk() ([][]byte, error) {
	var content []byte
	for _, urn := range m.urns {
		content = append(content, []byte(urn.String())...)
	}
	// "manifest", <chunk-size>, <file-size>
	return chunk([]interface{}{kManifest, constChunkSize, len(content)}, content)
}

type raw struct {
	content []byte
}

func (r raw) Chunk() ([][]byte, error) {
	return chunk([]interface{}{kRaw}, r.content)
}

// Constant Chunking -- in use

const (
	constChunkSize = 32 * 1024 // 32 Kibibytes
)

func chunk(eachChunk []interface{}, content []byte) (o [][]byte, err error) {
	var buf bytes.Buffer

	// 1. Determine byte overhead.
	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &buf).Encode(eachChunk)
	if err != nil {
		return
	}
	overhead := buf.Len()
	buf.Reset()

	// 2. Chunk (if needed)
	for len(content) > constChunkSize-overhead {
		toChunk := content[:constChunkSize-overhead]
		content = content[constChunkSize-overhead:]

		v := make([]interface{}, len(eachChunk)+1)
		copy(v, eachChunk)
		v[len(v)-1] = toChunk

		err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &buf).Encode(v)
		if err != nil {
			return
		}

		if buf.Len() != constChunkSize {
			err = fmt.Errorf("dshards chunking encoded %d of %d bytes", buf.Len(), constChunkSize)
			return
		}

		res := make([]byte, constChunkSize)
		copy(res, buf.Bytes())
		o = append(o, res)

		buf.Reset()
	}

	// 3. Final chunk (<= constChunkSize-overhead), pad if needed
	v := make([]interface{}, len(eachChunk)+1)
	copy(v, eachChunk)
	v[len(v)-1] = content

	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &buf).Encode(v)
	if err != nil {
		return
	}

	res := make([]byte, constChunkSize)
	copy(res, buf.Bytes())
	o = append(o, res)

	buf.Reset()
	return
}

// Variadic Chunking -- not yet used

var allowedChunkSizesIncreasingOrder = []int{
	1 * 1024,  // 1 Kibibyte
	2 * 1024,  // 2 Kibibytes
	4 * 1024,  // 4 Kibibytes
	8 * 1024,  // 8 Kibibytes
	16 * 1024, // 16 Kibibytes
	32 * 1024, // 32 Kibibytes
}

func exceedsLargestChunkSize(lenc int) bool {
	return lenc > allowedChunkSizesIncreasingOrder[len(allowedChunkSizesIncreasingOrder)-1]
}

// chunker takes a given content length and returns the next chunk size to use.
//
// Intended to be called iteratively, as the remaining content length shrinks.
func chunkerFn(lenc int) int {
	for _, size := range allowedChunkSizesIncreasingOrder {
		if lenc <= size {
			return size
		}
	}
	return allowedChunkSizesIncreasingOrder[len(allowedChunkSizesIncreasingOrder)-1]
}
