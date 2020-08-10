package dshards

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/cjslep/syrup"
)

func decode(b []byte) (r *Result, err error) {
	buf := bytes.NewBuffer(b)
	var v interface{}
	err = syrup.NewDecoder(syrup.NewPrototypeEncoding(), buf).Decode(&v)
	if err != nil {
		return
	}

	if vs, ok := v.([]interface{}); !ok {
		err = fmt.Errorf("decoded datashard is not into a []interface{}: %T", v)
		return
	} else {
		var isManifest bool
		if len(vs) < 2 {
			err = fmt.Errorf("decoded datashard len < 1: %d", len(vs))
			return
		} else if s, ok := vs[0].(string); !ok {
			err = fmt.Errorf("decoded datashard 0th element not string: %T", vs[0])
			return
		} else {
			if s == kManifest {
				isManifest = true
				if len(vs) != 4 {
					err = fmt.Errorf("decoded manifest datashard len != 4: %d", len(vs))
					return
				}
			} else if s == kRaw {
				isManifest = false
				if len(vs) != 2 {
					err = fmt.Errorf("decoded content datashard len != 2: %d", len(vs))
					return
				}
			} else {
				err = fmt.Errorf("decoded datashard unknown entry type: %s", s)
				return
			}
		}

		r = &Result{}
		if isManifest {
			if l, ok := vs[2].(int64); !ok {
				err = fmt.Errorf("decoded datashard manifest entry content len invalid type: %T", vs[2])
				return
			} else {
				r.contentLen = l
			}
			if b, ok := vs[3].([]byte); !ok {
				err = fmt.Errorf("decoded datashard manifest entry content invalid type: %T", vs[3])
				return
			} else {
				ss := strings.Split(string(b), urnPrefix+urnDelim)
				r.fetch = make([]URN, len(ss))
				for i, s := range ss {
					r.fetch[i], err = ParseURN(fmt.Sprintf("%s%s%s", urnPrefix, urnDelim, s))
					if err != nil {
						return
					}
				}
			}
		} else {
			if b, ok := vs[1].([]byte); !ok {
				err = fmt.Errorf("decoded datashard raw entry content invalid type: %T", vs[1])
				return
			} else {
				r.content = b
			}

		}
	}
	return
}
