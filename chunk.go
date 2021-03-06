package chunk

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sort"
)

// InspectConfig - configure parameters into the inspection process, passing nil will use default
type InspectConfig struct {
	//default 4
	StepSize int
	// how far to scan into the binary default 10meg, -1 means the whole file
	ScanSize int64
	// while scanning what size to garbage collect patterns
	WindowSize int64
	// group consecutive byte chunks until we're over this byte limit 40k default
	ChunkSize int64 // (this makes manageable diffing chunks); otherwise we'd have a million chunks
	// specify the hasher method to use its eaither sha256 or md5, default md5
	HashMeth string
	// pass in a pre figured out pattern
	PickPattern uint32
}

// FileChunkDesc - output from analyze, describes chunks a file contains
type FileChunkDesc struct {
	HashMeth  string
	Pat       uint32
	ChunkSize int64
	Count     int
	Chunks    []chunk
}

// Stats - report back some analyasis stats, useful possibly to inspect making better pattern finders
type Stats struct {
	AnalyzeSize           int64
	WindowSize            int64
	FileSize              int64
	PatternUsed           uint32
	RawChunkCount         int
	GroupedChunkCount     int
	GroupingChunkByteSize int64
	Picked                PatternInfo
	Top10Patterns         []PatternInfo
}

// PatternInfo - description of specific 4 byte pattern; when analyze is preformed
type PatternInfo struct {
	Pat         uint32
	Count       int
	PosMin      int64
	PosMax      int64
	AvgByteSpan int64
	Conseq      int
}

const oneK = 1024
const oneMeg = oneK * oneK

var defaultConfig = InspectConfig{
	4,
	10 * oneMeg,
	10 * oneMeg,
	400 * oneK,
	"md5",
	0,
}

func GetDefaultConfig() InspectConfig {
	return defaultConfig
}

type usage struct {
	pat    uint32
	cnt    int
	min    int64
	max    int64
	avg    int64
	conseq int
}

type chunk struct {
	hash   string
	pat    uint32
	offset int64
	size   int64
	consq  int
}

const patternSize = 4
const byteBitSize = 8

func (fcd *FileChunkDesc) Write(out io.Writer) error {
	return writePatchInfo(out, fcd.Chunks, fcd.ChunkSize, fcd.HashMeth)
}

// ReadFileChunkDesc - create a FileChunkDesc from a serialized version
func ReadFileChunkDesc(in bufio.Reader) (*FileChunkDesc, error) {
	return readPatchInfo(in)
}

func Scan(in io.ReadSeeker, size int64) (*Stats, error) {
	config := defaultConfig

	config.WindowSize = size
	config.ScanSize = -1

	stats := &Stats{}

	pats := collectPatterns(in, &config, stats)
	pickPattern(pats, stats)

	return stats, nil
}

// Analyze2 - inspect the input stream for a pattern then write out the chunks to the out stream
func Analyze2(in io.ReadSeeker, config *InspectConfig) (*FileChunkDesc, *Stats, error) {

	if config == nil {
		config = &defaultConfig
	}

	stats := &Stats{}
	stats.AnalyzeSize = config.ScanSize

	pats := collectPatterns2(in, config, stats)
	pick := pickPattern2(pats, stats)

	stats.PatternUsed = pick.pat

	chunks, err := groupChunks(in, pick.pat, config.ChunkSize, pick.cnt, config.HashMeth, stats)
	if err != nil {
		return nil, nil, err
	}

	ret := FileChunkDesc{
		HashMeth:  config.HashMeth,
		Pat:       pick.pat,
		ChunkSize: config.ChunkSize,
		Chunks:    chunks,
		Count:     len(chunks),
	}

	return &ret, stats, nil
}

// Analyze - inspect the input stream for a pattern then write out the chunks to the out stream
func Analyze(in io.ReadSeeker, config *InspectConfig) (*FileChunkDesc, *Stats, error) {

	if config == nil {
		config = &defaultConfig
	}

	stats := &Stats{}
	stats.AnalyzeSize = config.ScanSize

	hintCount := 0

	if config.PickPattern == 0 {
		pats := collectPatterns(in, config, stats)
		pick := pickPattern(pats, stats)
		stats.PatternUsed = pick.pat
		hintCount = pick.cnt
	} else {
		stats.PatternUsed = config.PickPattern
		hintCount = 1000
	}

	chunks, err := groupChunks(in, stats.PatternUsed, config.ChunkSize, hintCount, config.HashMeth, stats)
	if err != nil {
		return nil, nil, err
	}

	ret := FileChunkDesc{
		HashMeth:  config.HashMeth,
		Pat:       stats.PatternUsed,
		ChunkSize: config.ChunkSize,
		Chunks:    chunks,
		Count:     len(chunks),
	}

	return &ret, stats, nil
}

func writePatchInfo(out io.Writer, chunks []chunk, chunkSize int64, hashMeth string) error {
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

	var patU uint32 = 0
	if len(chunks) > 0 {
		patU = chunks[0].pat
	}

	pat := strconv.FormatUint(uint64(patU), 10)
	cnt := strconv.FormatUint(uint64(len(chunks)), 10)

	err := writeLine(fmt.Sprint("pat: ", pat, " csize: ", chunkSize, " count: ", cnt, " hm: ", hashMeth))
	if err != nil {
		return err
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

func readPatchInfo(in bufio.Reader) (*FileChunkDesc, error) {

	ret := FileChunkDesc{}

	if err := readHeader(in, &ret); err != nil {
		return nil, err
	}

	var err error
	var chk chunk
	for err = readChunk(in, &chk); err == nil || (err == io.EOF && chk.hash != ""); err = readChunk(in, &chk) {
		ret.Chunks = append(ret.Chunks, chk)
	}

	if err != nil && err != io.EOF {
		fmt.Println("Failed parsing chunks err: ", err)
		return nil, err
	}

	return nil, nil
}

func readChunk(r bufio.Reader, chk *chunk) error {
	/*
	   h: _j03U-pV8rUpqjrlH3mp3R9F2Jvy9NS8xPgumxSnu0Q=
	   o: 0
	   s: 41252
	*/
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
				v, err := strconv.ParseInt(strings.Trim(parts[1], " \n"), 10, 64)
				if err != nil {
					return err
				}
				chk.offset = v
			}
		case "s":
			{
				v, err := strconv.ParseInt(strings.Trim(parts[1], " \n"), 10, 64)
				if err != nil {
					return err
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

	return err
}

func readHeader(r bufio.Reader, fcd *FileChunkDesc) error {
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
				fcd.Pat = uint32(pV)
				return err
			}
		case "csize:":
			cap = func(v string) error {
				pV, err := strconv.ParseInt(v, 10, 64)
				fcd.ChunkSize = pV
				return err
			}
		case "count:":
			cap = func(v string) error {
				pV, err := strconv.ParseInt(v, 10, 64)
				fcd.Count = int(pV)
				return err
			}
		case "hm:":
			cap = func(v string) error {
				fcd.HashMeth = v
				return nil
			}
		}
	}

	return nil
}

func newHasher(meth string) hash.Hash {
	if meth == "sha256" {
		return sha256.New()
	}
	return md5.New()
}

func groupChunks(in io.ReadSeeker, pat uint32, chunkSize int64, hintCount int, hmeth string, stats *Stats) ([]chunk, error) {
	var chunks []chunk
	var err error

	use := usage{pat: pat}

	_, err = in.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("groupChunks, seek to head failed %v", err.Error())
	}

	chunks, err = chunkStream(in, use.pat, hintCount, hmeth)
	if err != nil {
		return nil, fmt.Errorf("groupChunks, failed to chunkStream: %v", err.Error())
	}

	stats.RawChunkCount = len(chunks)

	chunks, err = bundleChunks(in, chunks, chunkSize, hmeth)
	if err != nil {
		return nil, fmt.Errorf("groupChunks, failed to bundleChunks: %v", err.Error())
	}

	stats.GroupingChunkByteSize = chunkSize
	stats.GroupedChunkCount = len(chunks)
	if len(chunks) > 0 {
		stats.FileSize = chunks[len(chunks)-1].offset + chunks[len(chunks)-1].size
	} else {
		stats.FileSize = 0
	}

	return chunks, nil
}

func bundleChunks(in io.ReadSeeker, chunks []chunk, budget int64, hmeth string) ([]chunk, error) {
	ret := make([]chunk, 0, budget+1)

	var used int64
	var begin = 0

	hasher := newHasher(hmeth)

	// fmt.Printf("Bundling %v chunks, budget %v\n", len(chunks), budget)

	{
		var buf [1024]byte
		var start int64
		var end int64

		for i := 0; i < len(chunks); i++ {
			if used < budget {
				used += chunks[i].size
			}

			if used >= budget {
				// rehash
				start = chunks[begin].offset
				end = start + used

				var off = start
				hasher.Reset()

				if _, serr := in.Seek(start, 0); serr != nil {
					return nil, serr
				}

				for off < end {
					n, err := in.Read(buf[:])
					if err != nil && (err != io.EOF || n == 0) {
						break
					}
					hsz := int64(n)
					if off+hsz >= end {
						hsz = end - off
					}
					if _, herr := hasher.Write(buf[0:hsz]); herr != nil {
						return nil, herr
					}
					off += int64(n)
				}

				reChunk := chunks[begin]
				reChunk.hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))
				reChunk.size = end - start

				ret = append(ret, reChunk)

				used = 0
				begin = i + 1
			}
		}

		if used > 0 {
			start = chunks[begin].offset
			end = chunks[len(chunks)-1].offset + chunks[len(chunks)-1].size

			var off = start
			hasher.Reset()

			if _, serr := in.Seek(start, 0); serr != nil {
				return nil, serr
			}

			for off < end {
				n, err := in.Read(buf[:])
				if err != nil && n == 0 {
					break
				}
				hsz := int64(n)
				if off+hsz >= end {
					hsz = end - off
				}
				if _, herr := hasher.Write(buf[0:hsz]); herr != nil {
					return nil, herr
				}
				off += int64(n)
			}

			reChunk := chunks[begin]
			reChunk.hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))
			reChunk.size = end - start

			ret = append(ret, reChunk)
		}
	}

	return ret, nil
}

func chunkStream(in io.Reader, pickedPattern uint32, hintCount int, hmeth string) ([]chunk, error) {
	var off int64

	chunks := make([]chunk, 0, hintCount)

	var data [4]byte

	var pat uint32

	hasher := newHasher(hmeth)

	chk := chunk{"", pickedPattern, 0, 0, 0}

	var decoded [4]byte
	var decodePat = func() []byte {
		decoded[0] = byte(pat >> 24)
		decoded[1] = byte(pat >> 16)
		decoded[2] = byte(pat >> 8)
		decoded[3] = byte(pat)
		return decoded[:]
	}

	var sz int
	var err error

	for sz, err = in.Read(data[:]); err == nil || (err == io.EOF && sz > 0); sz, err = in.Read(data[:]) {
		pat = 0
		for i := 0; i < sz; i++ {
			pat |= uint32(data[i]) << uint(byteBitSize*((patternSize-1)-i))
		}

		if pat == pickedPattern {
			if off == chk.offset+int64((chk.consq+1)*patternSize) {
				chk.consq++ // consume consecutive matching patterns
				d := decodePat()
				hasher.Write(d)
				pat = 0
			} else {
				// we hit a new pattern so the current chunk gets pushed
				chk.size = off - chk.offset
				chk.hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))
				chunks = append(chunks, chk)

				chk = chunk{"", pickedPattern, off, 0, 0}
				hasher.Reset()

				hasher.Write(decodePat())
			}
		} else {
			hasher.Write(decodePat())
		}
		off += int64(sz)

		if err == io.EOF {
			break
		}
	}

	// exited above due to eof, but still had some trailing bytes
	chk.size = off - chk.offset
	if chk.size > 0 {
		chk.hash = base64.URLEncoding.EncodeToString(hasher.Sum(nil))
		chunks = append(chunks, chk)
	}

	// debugDump("dump.txt", chunks)

	return chunks, nil
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

func collectPatterns2(in io.Reader, config *InspectConfig, stats *Stats) ([]*usage) {
	var off int64

	pats := make([]*usage, 0, 1024 * 10)

	path := make(map[uint32]int)

	var data [4]byte

	var pat uint32

	for sz, err := in.Read(data[:]); err == nil || (err == io.EOF && sz > 0); sz, err = in.Read(data[:]) {
		pat = 0
		for i := 0; i < sz; i++ {
			pat |= uint32(data[i]) << uint(byteBitSize*((patternSize-1)-i))
		}

		var st *usage

		idx, ok := path[pat]
		if ok {
			st = pats[idx]
			st.cnt++

			if idx > 0 && pats[idx-1].cnt < st.cnt {
				find := sort.Search(len(pats)-idx, func (i int) bool { return pats[i].cnt <= st.cnt; })
				if find < len(pats)-idx {
				//	log.Print("Find+1 ", find+1, " find ", find, " index ", idx)
					copy(pats[find+1:], pats[find:idx])
					pats[find] = st
					path[pat] = find
				}
			}

			//find := idx - 1
			//for ;find > -1 && st.cnt > pats[find].cnt; find-- { }
			//find++
			//copy(pats[find+1:], pats[find:idx])
			//pats[find] = st
			//path[pat] = find
		} else {
			st = &usage{pat: pat, min: off, cnt: 1}
			if len(pats) < cap(pats) || off < config.ScanSize || config.ScanSize == -1 {
				pats = append(pats,st)
				path[pat] = len(pats)-1
			} else {
				// else don't add it
				off += int64(sz)
				if err == io.EOF {
					break
				} else {
					continue
				}
			}
		}

		if st.max < off {
			if st.max == off-patternSize {
				st.conseq++
				st.cnt--
			} else {
				if st.max != 0 {
					st.avg = (st.avg + (off - st.max)) / 2
				}
			}
			st.max = off
		}

		off += int64(sz)
		if err == io.EOF {
			break
		}
	}

	log.Print("Done with analasis")

	stats.AnalyzeSize = off

	return pats
}

func sortPatterns(pats map[uint32]usage, amt int) []usage {
	keep := make([]usage, amt)
	for _, usage := range pats {
		find := sort.Search(len(keep), func (i int) bool { return usage.cnt > keep[i].cnt || (usage.cnt == keep[i].cnt && usage.min < keep[i].min); })
		if find < len(keep) {
			if find+1 < len(keep) {
				copy(keep[find+1:],keep[find:])
			}
			keep[find] = usage
		}
	}

	return keep
}

func collectPatterns(in io.Reader, config *InspectConfig, stats *Stats) []usage {
	var off int64

	pats := make(map[uint32]usage)

	var data [4]byte

	var pat uint32

	gcPats := func (amt int) map[uint32]usage {
		//log.Print("GCing patterns keeping ", amt)
		keep := sortPatterns(pats, amt)

		ret := make(map[uint32]usage, amt)
		for _, v := range keep {
			ret[v.pat] = v
		}

		return ret
	}

	for sz, err := in.Read(data[:]); (err == nil || (err == io.EOF && sz > 0)) && (config.ScanSize == -1 || off < config.ScanSize); sz, err = in.Read(data[:]) {

		if config.WindowSize > 0 && (off % config.WindowSize) == 0 && len(pats) > 0 {
			// garbage collect this only keeping the top 1000 by cnt
			pats = gcPats(1000)
		}

		pat = 0
		for i := 0; i < sz; i++ {
			pat |= uint32(data[i]) << uint(byteBitSize*((patternSize-1)-i))
		}

		st, ok := pats[pat]
		if !ok {
			st = usage{pat: pat, min: off}
		}
		st.cnt++
		if st.max < off {
			if st.max == off-patternSize {
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
		off += int64(sz)
		if err == io.EOF {
			break
		}
	}

	stats.AnalyzeSize = off
	stats.WindowSize = config.WindowSize

	return sortPatterns(pats, 1000)
}

func pickPattern2(pats []*usage, stats *Stats) usage {
	var pick *usage

	for _, v := range pats[0:10] {
		if v.pat == 0 {
			if len(pats) == 1 {
				pick = v
			}
			continue
		} else {
			if pick == nil || pick.cnt == 0 {
				pick = v
			}
			if v.cnt <= int(float32(pick.cnt)*.4) {
				pick = v
				break
			}
		}
	}

	for _, v := range pats[0:10] {
		stats.Top10Patterns = append(stats.Top10Patterns, PatternInfo{Count: v.cnt,
			AvgByteSpan: v.avg,
			Conseq:      v.conseq,
			Pat:         v.pat,
			PosMax:      v.max,
			PosMin:      v.min,
		})
	}

	return *pick
}

func pickPattern(top []usage, stats *Stats) usage {
	var pick usage

	top = top[0:10]

	// pick the pattern with some chunkiness but not too granular
	//  so the .4 below here is picking a pattern that is 40% smaller then the current pick
	//  this tends to be a good pick you want something that isn't too granular
	//  usually 40% is a good trade off because most things are close in number, but you want not the most occuring and
	//  also not the least occuring, so this is trying to pick one or two candidates down from the most occuring (in the top 10)
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

	for _, v := range top {
		stats.Top10Patterns = append(stats.Top10Patterns, PatternInfo{Count: v.cnt,
			AvgByteSpan: v.avg,
			Conseq:      v.conseq,
			Pat:         v.pat,
			PosMax:      v.max,
			PosMin:      v.min,
		})
	}

	stats.Picked = PatternInfo{Count: pick.cnt,
		AvgByteSpan: pick.avg,
		Conseq: pick.conseq,
		Pat: pick.pat,
		PosMax: pick.max,
		PosMin: pick.min,
	}

	stats.PatternUsed = stats.Picked.Pat

	return pick
}
