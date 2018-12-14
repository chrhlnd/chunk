package chunk

import (
	"io"
	"os"
)

type rs struct {
	f      *os.File
	buf    []byte
	buflen int
	pos    int
	eof    bool
}

func (r *rs) Read(buffer []byte) (int, error) {

	want := len(buffer)

	bpos := 0

	for want > 0 {
		//fmt.Printf("Want %v pos %v len %v eof %v\n", want, r.pos, len(r.buf), r.eof)
		if r.pos < r.buflen {

			size := r.buflen - r.pos
			if size > want {
				size = want
			}

			//fmt.Printf("Copying %v amount at pos %v\n", size, r.pos)
			if bpos == 0 && size <= 4 {
				switch size - 1 {
				case 3:
					buffer[3] = r.buf[r.pos+3]
					fallthrough
				case 2:
					buffer[2] = r.buf[r.pos+2]
					fallthrough
				case 1:
					buffer[1] = r.buf[r.pos+1]
					fallthrough
				case 0:
					buffer[0] = r.buf[r.pos+0]
					break

				}
			} else {
				copy(buffer[bpos:bpos+size], r.buf[r.pos:r.pos+size])
			}
			r.pos += size
			bpos += size
			want -= size
		}

		if want > 0 {
			if r.eof {
				return bpos, io.EOF
			}

			err := r.Fill()
			if err != nil && err != io.EOF {
				return -1, err
			}
		}
	}
	return bpos, nil
}

func (r *rs) Fill() error {
	if r.eof {
		return io.EOF
	}

	n, err := r.f.Read(r.buf[0:cap(r.buf)])
	if err != nil && err != io.EOF {
		return err
	}
	if err == io.EOF {
		r.eof = true
	}
	r.buf = r.buf[0:n]
	r.buflen = n
	r.pos = 0

	return nil
	//fmt.Printf("filled -> Want %v pos %v len %v\n", want, r.pos, len(r.buf))
}

func (r *rs) Seek(offset int64, whence int) (int64, error) {
	// WIP: could be smarter here, if we seek within buffer range could just adjust pointers
	pos, err := r.f.Seek(offset, whence)
	if err != nil {
		return -1, err
	}

	r.buf = r.buf[:0]
	r.buflen = 0
	r.pos = 0
	r.eof = false
	return pos, nil
}

// NewReadSeeker - create a buffered reader that can seek too
func NewReadSeeker(f *os.File, bufSz int) io.ReadSeeker {
	return &rs{f, make([]byte, 0, bufSz), 0, 0, false}
}
