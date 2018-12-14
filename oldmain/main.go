package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
)

var gen = flag.Bool("gen", false, "generate patch info")
var chk = flag.Bool("chk", false, "check patch info")
var pinfo = flag.String("pinfo", ".pinfo", "Use this extension when scanning for patch files on the commandline")
var cpuprof = flag.Bool("cpuprofile", false, "write cpu profile")
var memprof = flag.Bool("memprofile", false, "write memory profile")
var huse = flag.String("hash", "md5", "md5|sha256 sha is slower may matter")

func newHasher() hash.Hash {
	if *huse == "sha256" {
		return sha256.New()
	}
	return md5.New()
}

type usage struct {
	pat    uint32
	cnt    int
	min    uint64
	max    uint64
	avg    uint64
	conseq int
}

type chunk struct {
	hash   string
	pat    uint32
	offset uint64
	size   uint64
	consq  int
}

type patchFile struct {
	pat       uint32
	chunkSize int
	count     int
	chunks    []*chunk
	had       int
	dup       int
}

func (p *patchFile) readHeader(r *bufio.Reader) error {
	//pat: 0 csize: 40960 count: 47
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}

	var cap func(string) error
	for _, v := range strings.Split(line, " ") {
		if cap != nil {
			tv := strings.Trim(v, "\n")
			err = cap(tv)
			cap = nil
			if err != nil {
				return err
			}
			continue
		}

		trimmed := strings.Trim(v, " \n")
		switch trimmed {
		case "pat:":
			cap = func(v string) error {
				pV, err := strconv.ParseUint(v, 10, 32)
				p.pat = uint32(pV)
				return err
			}
		case "csize:":
			cap = func(v string) error {
				pV, err := strconv.ParseInt(v, 10, 64)
				p.chunkSize = int(pV)
				return err
			}
		case "count:":
			cap = func(v string) error {
				pV, err := strconv.ParseInt(v, 10, 64)
				p.count = int(pV)
				return err
			}
		}
	}

	return nil
}

func (p *patchFile) readChunk(r *bufio.Reader) (*chunk, error) {
	/*
	   h: _j03U-pV8rUpqjrlH3mp3R9F2Jvy9NS8xPgumxSnu0Q=
	   o: 0
	   s: 41252
	*/
	chk := &chunk{}

	var line string
	var err error

READ:
	for line, err = r.ReadString('\n'); err == nil || (err == io.EOF && len(line) > 0); line, err = r.ReadString('\n') {
		parts := strings.Split(line, ":")
		switch parts[0] {
		case "h":
			chk.hash = strings.Trim(parts[1], " \n")
		case "o":
			{
				v, err := strconv.ParseUint(strings.Trim(parts[1], " \n"), 10, 64)
				if err != nil {
					return nil, err
				}
				chk.offset = v
			}
		case "s":
			{
				v, err := strconv.ParseUint(strings.Trim(parts[1], " \n"), 10, 64)
				if err != nil {
					return nil, err
				}
				chk.size = v
				break READ
			}
		default:
			{
				fmt.Println("got case?? ", parts[0], " line was ", line)
			}
		}
	}

	return chk, err
}

func (p *patchFile) Parse(f *os.File) error {
	r := bufio.NewReader(f)
	err := p.readHeader(r)
	if err != nil {
		return err
	}

	var chk *chunk
	for chk, err = p.readChunk(r); err == nil || (err == io.EOF && chk.hash != ""); chk, err = p.readChunk(r) {
		p.chunks = append(p.chunks, chk)
	}

	if err != nil && err != io.EOF {
		fmt.Println("Failed parsing chunks err: ", err)
		return err
	}

	return nil
}

func (p *patchFile) Dump(to io.Writer) error {
	w := bufio.NewWriter(to)

	//	//pat: 0 csize: 40960 count: 47
	_, err := w.WriteString(fmt.Sprint("pat: ", p.pat, " csize: ", p.chunkSize, " count: ", len(p.chunks), " had: ", p.had, "\n"))
	if err != nil {
		return err
	}
	/*
	   h: _j03U-pV8rUpqjrlH3mp3R9F2Jvy9NS8xPgumxSnu0Q=
	   o: 0
	   s: 41252
	*/
	for _, v := range p.chunks {

		_, err = w.WriteString(fmt.Sprint("h: ", v.hash, "\n"))
		if err != nil {
			return err
		}

		_, err = w.WriteString(fmt.Sprint("o: ", v.offset, "\n"))
		if err != nil {
			return err
		}

		_, err = w.WriteString(fmt.Sprint("s: ", v.size, "\n"))
		if err != nil {
			return err
		}
	}

	w.Flush()

	return nil
}

func getPat(buf []byte) uint32 {
	var ret uint32

	for i := 0; i < len(buf); i++ {
		ret |= uint32(buf[i]) << uint(8*(3-i))
	}

	return ret
}

func writeNeedSpec(out io.Writer, need *patchFile) error {
	if len(need.chunks) == 0 {
		return nil
	}

	w := bufio.NewWriter(out)

	pat := strconv.FormatUint(uint64(need.pat), 10)
	cnt := strconv.FormatUint(uint64(len(need.chunks)), 10)

	byteReq := uint64(0)
	for _, c := range need.chunks {
		byteReq += c.size
	}

	_, err := w.WriteString(fmt.Sprint("pat: ", pat, " csize: ", need.chunkSize, " count: ", cnt, " had: ", need.had, " dup: ", need.dup, " pbytes: ", byteReq, "\n"))
	if err != nil {
		return err
	}

	if false {
		for _, c := range need.chunks {
			_, err = w.WriteString(fmt.Sprint("h: ", c.hash, "\n"))
			if err != nil {
				return err
			}
			_, err = w.WriteString(fmt.Sprint("o: ", c.offset, "\n"))
			if err != nil {
				return err
			}
			_, err = w.WriteString(fmt.Sprint("s: ", c.size, "\n"))
			if err != nil {
				return err
			}
		}
	}

	w.Flush()

	return nil
}

func writeSpec(out io.Writer, chunks []chunk, chunkSize int) error {
	writeLine := func(value string) error {
		_, err := io.WriteString(out, value)
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, "\n")
		if err != nil {
			return err
		}
		return nil
	}

	writeField := func(label, value string) error {
		_, err := io.WriteString(out, label)
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, value)
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, "\n")
		if err != nil {
			return err
		}

		return nil
	}

	if len(chunks) > 0 {
		pat := strconv.FormatUint(uint64(chunks[0].pat), 10)
		cnt := strconv.FormatUint(uint64(len(chunks)), 10)

		err := writeLine(fmt.Sprint("pat: ", pat, " csize: ", chunkSize, " count: ", cnt))
		if err != nil {
			return err
		}
	}

	for _, c := range chunks {
		err := writeField("h: ", c.hash)
		if err != nil {
			return err
		}
		err = writeField("o: ", strconv.FormatUint(uint64(c.offset), 10))
		if err != nil {
			return err
		}
		err = writeField("s: ", strconv.FormatUint(uint64(c.size), 10))
		if err != nil {
			return err
		}
	}

	return nil
}

func verify(f *os.File, chunks []chunk) bool {
	buf := make([]byte, 4096)

	failed := false

	for i, ch := range chunks {
		_, err := f.Seek(int64(ch.offset), 0)
		if err != nil {
			fmt.Println("Error seeking in chunk ", i, " err:", err)
		}

		if ch.size > uint64(len(buf)) {
			buf = make([]byte, ch.size)
		}

		ptr := buf[0:ch.size]

		_, err = f.Read(ptr)

		hasher := newHasher()

		hasher.Write(ptr)
		hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

		if ch.hash != hash {
			fmt.Println("Failing has ", i, " expected ", ch.hash, " had ", hash)
			failed = true
		}
	}
	if !failed {
		fmt.Println("Hashes verified")
	}

	return !failed
}

var buffer []byte

func hashChunkFP(f *os.File, pat uint32, off uint64, size uint64) (chunk, error) {
	ret := chunk{hash: "", pat: pat, offset: off, size: size}

	if size > uint64(len(buffer)) {
		buffer = make([]byte, size)
	}

	buf := buffer[0:size]

	n, err := f.ReadAt(buf, int64(off))
	if err != nil {
		return ret, err
	}

	if uint64(n) != size {
		return ret, fmt.Errorf("Wrong size")
	}

	hasher := newHasher()
	hasher.Write(buf[0:n])
	ret.hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	return ret, nil
}

func hashChunk(fName string, pat uint32, off uint64, size uint64) (chunk, error) {
	ret := chunk{hash: "", pat: pat, offset: off, size: size}

	f, err := os.Open(fName)
	if err != nil {
		return ret, err
	}

	buf := make([]byte, size)

	n, err := f.ReadAt(buf, int64(off))
	if err != nil {
		return ret, err
	}

	if uint64(n) != size {
		f.Close()
		return ret, fmt.Errorf("Wrong size")
	}

	f.Close()

	hasher := newHasher()
	hasher.Write(buf[0:n])
	ret.hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	return ret, nil
}

func groupit(f *os.File, chunks []chunk, budget int) ([]chunk, error) {
	ret := make([]chunk, 0, budget+1)
	//var lock sync.Mutex

	var used uint64
	startAt := 0

	errch := make(chan (error), 5)

	var wg sync.WaitGroup
	var err error

	go func() {
		for v := range errch {
			err = v
		}
	}()

	hashNow := func(i int) {
		//wg.Add(1)
		//queueLimit <- true
		func(s int, u uint64) {
			//defer wg.Done()

			c, err := hashChunkFP(f, chunks[s].pat, chunks[s].offset, u)
			if err != nil {
				errch <- err
				//<-queueLimit
				return
			}

			//lock.Lock()
			ret = append(ret, c)
			//lock.Unlock()
			//<-queueLimit
		}(startAt, used)
		used = 0
		startAt = i + 1
	}

	for i := 0; i < len(chunks); i++ {
		if used < uint64(budget) {
			used += chunks[i].size
		}

		if used >= uint64(budget) {
			hashNow(i)
		}
	}

	if used > 0 {
		hashNow(len(chunks))
	}

	wg.Wait()
	close(errch)

	return ret, err
}

var queueLimit = make(chan bool, 1)

func queueHash(wg *sync.WaitGroup, lock *sync.Mutex, errch chan error, f *os.File, c chunk, chunks *[]chunk) {
	//wg.Add(1)
	//queueLimit <- true

	//go func(c chunk) {
	//defer wg.Done()
	chk, err := hashChunkFP(f, c.pat, c.offset, c.size)
	if err != nil {
		errch <- err
		//<-queueLimit
		return
	}
	chk.consq = c.consq

	//lock.Lock()
	*chunks = append(*chunks, chk)
	//lock.Unlock()

	//<-queueLimit
	//}(c)
}

func chunkit(f *os.File, pat usage) ([]chunk, error) {
	_, err := f.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	chunks := make([]chunk, 0, pat.cnt)
	var lock sync.Mutex

	errch := make(chan (error), 5)

	var wg sync.WaitGroup
	var errAsync error

	go func() {
		for v := range errch {
			errAsync = v
		}
	}()

	var sz int

	chk := chunk{"", pat.pat, 0, 0, 0}

	totalOff := uint64(0)

	for sz, err = f.Read(buf); err == nil; sz, err = f.Read(buf) {
		track := func(off uint64, psz uint64, curp uint32) {
			if curp == pat.pat {
				//fmt.Println("T:", totalOff, " TestOff ", (chk.offset + uint64(chk.consq*4)))
				if totalOff == chk.offset+uint64((chk.consq+1)*4) {
					chk.consq++ // consume consecutive matching patterns
				} else {
					// we hit a new pattern so the current chunk gets pushed
					chk.size = totalOff - chk.offset
					//chk.hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))

					queueHash(&wg, &lock, errch, f, chk, &chunks)
					chk = chunk{"", pat.pat, totalOff, 0, 0}
				}
			}
			if psz < 4 {
				// last bit not divis by 4
				chk.size = totalOff - chk.offset
				queueHash(&wg, &lock, errch, f, chk, &chunks)
				chk = chunk{"", pat.pat, totalOff, 0, 0}
			}
		}

		var pchk uint64
		for ; pchk < uint64(sz/4); pchk++ {
			track(pchk*4, 4, getPat(buf[(pchk*4):(pchk*4)+4]))
			totalOff += 4
		}

		if pchk*4 < uint64(sz) {
			diff := uint64(sz) - (pchk * 4)

			track(pchk*4, diff, getPat(buf[(pchk*4):(pchk*4)+diff]))
			totalOff += diff
		}
	}

	chk.size = totalOff - chk.offset
	queueHash(&wg, &lock, errch, f, chk, &chunks)

	wg.Wait()
	close(errch)

	//debugDump("dump.txt", chunks)

	return chunks, errAsync
}

func debugDump(fname string, chunks []chunk) {
	f, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	for i, v := range chunks {
		f.WriteString(fmt.Sprintf("%v - %+v\n", i, v))
	}
	f.Close()
}

func getchunks(f *os.File, pat uint32, chunkSize int) ([]chunk, error) {
	var chunks []chunk
	var err error

	use := usage{pat: pat}

	chunks, err = chunkit(f, use)
	if err != nil {
		return nil, fmt.Errorf("getchunks, failed to chunkit: %v", err.Error())
	}

	fmt.Printf("Chunk count after chunkit %v\n", len(chunks))

	chunks, err = groupit(f, chunks, chunkSize)
	if err != nil {
		return nil, fmt.Errorf("getchunks, failed to groupit: %v", err.Error())
	}

	fmt.Printf("Chunk count after groupit %v\n", len(chunks))

	return chunks, nil
}

func analyze(f *os.File) {
	buf := make([]byte, 4096)

	var err error

	var pats map[uint32]usage
	var off uint64
	var sz int

	pats = make(map[uint32]usage)

	for sz, err = f.Read(buf); err == nil && off < 1024*1024*10; sz, err = f.Read(buf) {

		chunk := func(b []byte) {
			var pat uint32

			for i := 0; i < len(b); i++ {
				pat |= uint32(b[i]) << uint(8*(3-i))
			}

			st, ok := pats[pat]
			if !ok {
				st = usage{pat: pat, min: off}
			}
			st.cnt++
			if st.max < off {
				if st.max == off-4 {
					st.conseq++
					st.cnt--
				} else {
					if st.max != 0 {
						st.avg = (st.avg + (off - st.max)) / 2
					}
				}
				st.max = off
			}

			pats[pat] = st
			off += uint64(len(b))
		}

		var m int
		for ; m < sz/4; m++ {
			chunk(buf[m*4 : (m*4)+4])
		}

		if m*4 < int(sz) {
			chunk(buf[m*4 : (m*4)+(sz-(m*4))])
		}
	}

	top := make([]usage, 10)

	var dump = func(t []usage) {
		for i, v := range t {
			fmt.Print(i, " ", fmt.Sprintf("%+v", v), "\n")
		}
	}

	for _, v := range pats {
		for i := 0; i < len(top); i++ {
			if v.cnt > top[i].cnt {
				if i < len(top)-1 {
					for z := len(top) - 2; z >= i; z-- {
						top[z+1] = top[z]
					}
				}
				top[i] = v
				break
			}
		}
	}

	fmt.Println("Totla patterns ", len(pats))

	pats = nil

	var pick usage

	for _, v := range top {
		if v.pat == 0 {
			if len(top) == 1 {
				pick = v
			}
			continue
		} else {
			if pick.cnt == 0 {
				pick = v
			}
			if v.cnt <= int(float32(pick.cnt)*.4) {
				pick = v
				break
			}
		}
	}

	dump(top)
	fmt.Printf("Picked %+v\n", pick)

	var chunks []chunk

	stat, err := f.Stat()

	chunkSize := 1024 * 400

	chunks, err = getchunks(f, pick.pat, chunkSize)

	fmt.Println(" Chunk count: ", len(chunks))
	fmt.Println(" Chunk fsz  : ", chunks[len(chunks)-1].offset+chunks[len(chunks)-1].size)

	fmt.Println(" File size  : ", stat.Size())

	//if !verify(f, chunks) {
	//	os.Exit(1)
	//}

	name := f.Name()
	if name == "" {
		name = "a"
	}

	err = writePatchInfo(fmt.Sprint(name, *pinfo), chunks, chunkSize)
	if err != nil {
		fmt.Println(err)
	}
}

func writePatchInfo(pinfo string, chunks []chunk, chunkSize int) error {
	if pinfo == "" {
		pinfo = fmt.Sprint("a", strconv.Itoa(int(chunks[0].pat)), ".pinfo")
	}

	err := func(name string) error {
		w, err := os.Create(name)
		if err != nil {
			return err
		}

		defer func() {
			cerr := w.Close()
			if cerr != nil {
				fmt.Printf("Error closing: %v", cerr)
			}
		}()

		return writeSpec(w, chunks, chunkSize)
	}(pinfo)

	return err
}

func getNeed(baseSrc *os.File, patchSrc *os.File) (*patchFile, error) {
	p := patchFile{}
	err := p.Parse(patchSrc)
	if err != nil {
		return nil, err
	}

	var chunks []chunk

	chunks, err = getchunks(baseSrc, p.pat, p.chunkSize)
	if err != nil {
		return nil, err
	}

	have := make(map[string]bool, len(chunks))
	for _, v := range chunks {
		have[v.hash] = true
	}

	need := make(map[string]bool, len(p.chunks))

	needList := make([]*chunk, 0, 50)

	for _, c := range p.chunks {
		if _, ok := have[c.hash]; !ok {
			if _, ok := need[c.hash]; !ok {
				need[c.hash] = true
				needList = append(needList, c)
			} else {
				p.dup++
			}
		} else {
			p.had++
		}
	}

	p.chunks = needList

	/*
		for i := len(p.chunks) - 1; i > -1; i-- {
			if _, ok := have[p.chunks[i].hash]; ok {
				copy(p.chunks[i:], p.chunks[i+1:])
				p.chunks = p.chunks[0 : len(p.chunks)-1]
				p.had++
			}
		}
	*/

	return &p, nil
}

func patchFileExists(fname string) string {
	if _, err := os.Stat(fname + *pinfo); !os.IsNotExist(err) {
		return fname + *pinfo
	}
	return ""
}

func fileExists(fname string) string {
	if _, err := os.Stat(fname); !os.IsNotExist(err) {
		return fname
	}
	return ""
}

func doExit(err error) {
	if *memprof {
		f, err := os.Create("mem.profile")
		if err != nil {
			log.Fatal("Mem profile file create failed: ", err)
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("Mem profile failed to write: ", err)
		}
		f.Close()
	}

	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()

	if *cpuprof {
		f, err := os.Create("cpu.profile")
		if err != nil {
			log.Fatal("Cpu profile file open failed: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("Cpu profile failed to start: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	var err error

	if !*gen && !*chk {
		fmt.Println("Not doing anything, use -help")
	}

	if *gen {
		for _, v := range flag.Args() {
			var fn = func(name string) {
				var f *os.File

				f, err := os.Open(name)
				if err != nil {
					return
				}

				defer f.Close()

				analyze(f)
			}

			fn(v)

			if err != nil {
				fmt.Print(err)
				break
			}
		}

		if err != nil {
			doExit(err)
		}
	}

	if *chk {
		for _, v := range flag.Args() {

			file := fileExists(v)
			if file == "" {
				fmt.Println("Skipping; Can't check ", v, " couldn't find file")
				continue
			}

			pfile := patchFileExists(v)
			if pfile == "" {
				fmt.Println("Skipping; No patch file found for ", v)
				continue
			}

			var findNeeded = func(patch, base string) (*patchFile, error) {
				var bF *os.File
				var pF *os.File

				bF, err := os.Open(base)
				if err != nil {
					fmt.Println("Failed opening base file ", base, " for patch check; err: ", err)
					return nil, err
				}

				defer func() {
					err := bF.Close()
					if err != nil {
						fmt.Println("Failed closing base file ", base, " err; ", err)
					}
				}()

				pF, err = os.Open(patch)
				if err != nil {
					fmt.Println("Failed opening patch file ", patch, " for patch check; err: ", err)
					return nil, err
				}

				defer func() {
					err := pF.Close()
					if err != nil {
						fmt.Println("Failed closing patch file ", base, " err; ", err)
					}
				}()

				return getNeed(bF, pF)
			}

			patchNeed, err := findNeeded(pfile, file)

			if err != nil {
				fmt.Print(err)
				break
			}

			writeNeedSpec(os.Stdout, patchNeed)

			if len(patchNeed.chunks) == 0 {
				fmt.Println("File is in sync")
			}
		}
		if err != nil {
			doExit(err)
		}
	}

	doExit(nil)

}
