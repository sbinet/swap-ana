package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	freeze       = "/sys/fs/cgroup/freezer/system.slice/freezer.state"
	pagemapEntry = 8
)

var (
	maps   string
	pmap   string
	pagesz = uint64(os.Getpagesize())

	freq = flag.Duration("freq", 600*time.Second, "frequency for sampling")
)

func main() {
	flag.Parse()

	pid := flag.Arg(0)
	maps = filepath.Join("/proc", pid, "maps")
	pmap = filepath.Join("/proc", pid, "pagemap")
	iter := 0
	for {
		process(maps, iter)
		time.Sleep(*freq)
		iter++
	}
}

func process(fname string, iter int) {
	f, err := os.Open(fname)
	if err != nil {
		log.Fatalf("could not open [%s]: %v\n", fname, err)
	}
	defer f.Close()

	log.Printf("freezing process [%s]...\n", fname)
	err = ioutil.WriteFile(freeze, []byte("FROZEN\n"), 0755)
	if err != nil {
		log.Fatalf("error freezing process: %v\n", err)
	}

	defer func() {
		err = ioutil.WriteFile(freeze, []byte("THAWED\n"), 0755)
		if err != nil {
			log.Fatalf("error thawing process: %v\n", err)
		}
		log.Printf("freezing process [%s]... [done]\n\n", fname)
	}()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Bytes()
		if !bytes.Contains(line, []byte("[heap]")) {
			continue
		}
		pages := bytes.Split(line, []byte(" "))[0]
		var (
			beg uint64
			end uint64
		)
		_, err = fmt.Fscanf(bytes.NewReader(pages), "%x-%x", &beg, &end)
		if err != nil {
			log.Fatalf("error scanning heap range: %v\n", err)
		}
		log.Printf(">>> 0x%x-0x%x => %v kB\n", beg, end, (end-beg)/1024)
		analyze(beg, end, iter)
	}
}

func analyze(beg, end uint64, iter int) {
	f, err := os.Open(pmap)
	if err != nil {
		log.Fatalf("could not open [%s]: %v\n", pmap, err)
	}
	defer f.Close()

	out, err := os.Create(fmt.Sprintf("iter-%04d", iter))
	if err != nil {
		log.Fatalf("could not create [iter-%04d]: %v\n", iter, err)
	}
	defer out.Close()

	for addr := beg; addr < end; addr += 4096 {
		var buf [pagemapEntry]byte
		offset := int64(addr / pagesz * pagemapEntry)
		_, err = f.ReadAt(buf[:], offset)

		val := uint64(0)
		err = binary.Read(bytes.NewReader(buf[:]), binary.LittleEndian, &val)
		if err != nil {
			log.Fatalf("error reading pagemap entry: %v\n", err)
		}

		swapped := (val >> 62) & 1
		present := (val >> 63) & 1
		fmt.Fprintf(
			out,
			"%d\t0x%x\t\t%d\t%d%d\n",
			iter, addr, addr, present, swapped,
		)
	}

	err = out.Close()
	if err != nil {
		log.Fatalf("error closing [iter-%04d]: %v\n", iter, err)
	}
}
