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
var pinfo = flag.String("pinfo", ".pinfo", "Use this extension when scanning for patch files on the commandline")
var cpuprof = flag.Bool("cpuprofile", false, "write cpu profile")
var huse = flag.String("hash", "md5", "md5|sha256 sha is slower may matter")
var ssize = flag.Int("ssize", 10*1024*1024, "set the scan size to find a pattern")
var gsize = flag.Int("gsize", 400*1024, "set the grouping size to find a pattern")
var meth = flag.String("meth", "one", "pick one or two")

const bufferSize = 1024 * 64

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

				outf := name + ".pinfo"

				fout, err := os.Create(outf)
				if err != nil {
					return
				}

				defer fout.Close()

				cfg := chunk.GetDefaultConfig()
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

	fmt.Println("- ", fname, " -------------")
	fmt.Println("- Pattern      : ", stats.PatternUsed)
	fmt.Println("- AnalyzeSize  : ", stats.AnalyzeSize)
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
