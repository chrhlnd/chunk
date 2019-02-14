package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"

	"github.com/chrhlnd/chunk"
)

var gen = flag.Bool("gen", false, "generate patch info")
var chk = flag.Bool("chk", false, "check patch info")
var scan = flag.Bool("scan", false, "full scan of a file to find the best pattern")
var pinfo = flag.String("pinfo", ".pinfo", "Use this extension when scanning for patch files on the commandline")
var cpuprof = flag.Bool("cpuprofile", false, "write cpu profile")
var huse = flag.String("hash", "md5", "md5|sha256 sha is slower may matter")
var ssize = flag.Int("ssize", 10*1024*1024, "set the scan size to find a pattern")
var gsize = flag.Int("gsize", 400*1024, "set the grouping size to find a pattern")
var meth = flag.String("meth", "one", "pick one or two")
var verbose = flag.Bool("v", false, "print some extra stuff")
var pat = flag.Uint("pattern", 0, "if you know the pattern tell generate")

const bufferSize = 1024 * 64

func openRead(fname string, process func(f *os.File)) error {
	var f *os.File

	var err error

	f, err = os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	process(f)

	return nil
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

	if !*gen && !*chk && !*scan {
		fmt.Println("Not doing anything, use -help")
	}

	if *scan {
		if *verbose {
			fmt.Println("scanning")
		}
		for _, v := range flag.Args() {
			err := openRead(v, func(f *os.File) {
				stats, err := chunk.Scan(chunk.NewReadSeeker(f, bufferSize), 1024 * 1024 * 10)
				if err != nil {
					log.Fatal(err)
				}

				printStats(f.Name(), stats)
			})
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	if *gen {
		if *verbose {
			fmt.Println("generating")
		}
		for _, v := range flag.Args() {
			var fn = func(name string) {
				var f *os.File

				f, err := os.Open(name)
				if err != nil {
					return
				}
				defer f.Close()

				outf := name + ".pinfo"

				fout, err := os.Create(outf)
				if err != nil {
					return
				}

				defer fout.Close()

				cfg := chunk.GetDefaultConfig()
				if *pat != 0 {
					cfg.PickPattern = uint32(*pat)
				}
				cfg.ScanSize = int64(*ssize)
				cfg.ChunkSize = int64(*gsize)
				if *meth == "one" {
					fileDesc, stats, err := chunk.Analyze(chunk.NewReadSeeker(f, bufferSize), &cfg)
					if err != nil {
						log.Fatal(err)
					}

					printStats(f.Name(), stats)

					err = fileDesc.Write(fout)
					if err != nil {
						log.Fatal(err)
					}
				} else {
					fileDesc, stats, err := chunk.Analyze2(chunk.NewReadSeeker(f, bufferSize), &cfg)
					if err != nil {
						log.Fatal(err)
					}

					printStats(f.Name(), stats)

					err = fileDesc.Write(fout)
					if err != nil {
						log.Fatal(err)
					}
				}
			}

			fn(v)

			if err != nil {
				fmt.Print(err)
				break
			}
		}

		if err != nil {
			log.Fatal(err)
		}
	}
}

func printStats(fname string, stats *chunk.Stats) {
	fmt.Println("Pat", stats.Picked.Pat,
		"Cnt", stats.Picked.Count,
		"Min", stats.Picked.PosMin,
		"Max", stats.Picked.PosMax,
		"Avg", stats.Picked.AvgByteSpan,
		"Csq", stats.Picked.Conseq)

	fmt.Println("- ", fname, " -------------")
	fmt.Println("- Pattern      : ", stats.PatternUsed)
	fmt.Println("- AnalyzeSize  : ", stats.AnalyzeSize)
	fmt.Println("- WindowSize   : ", stats.WindowSize)
	fmt.Println("- FileSize     : ", stats.FileSize)
	fmt.Println("- RawChunks    : ", stats.RawChunkCount)
	fmt.Println("- GroupedChunks: ", stats.GroupedChunkCount)
	fmt.Println("- GroupSize    : ", stats.GroupingChunkByteSize)

	fmt.Println("- Top10 patterns")
	for i, v := range stats.Top10Patterns {
		fmt.Println("-- ",
			i,
			"- Pat:", v.Pat,
			"Cnt:", v.Count,
			"Min:", v.PosMin,
			"Max:", v.PosMax,
			"Avg:", v.AvgByteSpan,
			"Csq:", v.Conseq)
	}

}
