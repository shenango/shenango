package main

import (
	"net"
	"os"
	"fmt"
	"strconv"
	"time"
	"math"
	"log"
	"bytes"
	"encoding/binary"
)

func sqrt(n uint64) float64 {
	v := float64(0)
	for i := uint64(0); i < n; i++ {
		v += math.Sqrt(float64(2350845.545) * float64(i))
	}
	return v
}

func callibrate(n uint64) uint64 {
	start := time.Now()
	v := float64(0)
	for i := int(0); i < 10000; i++ {
		v += sqrt(n)
	}
	elapsed := time.Since(start)
	log.Printf("took %s %f", elapsed / 10000, v)
	return 0
}

func worker(n uint64, udpc *net.UDPConn, c chan uint64) {
	reqs := uint64(0)
	bs := make([]byte, 64)
	buf := bytes.NewBuffer(bs)

	for {
		err := binary.Write(buf, binary.LittleEndian, sqrt(n))
		if err != nil {
			break
		}

		_, err = udpc.Write(bs)
		if err != nil {
			break
		}

		_, err = udpc.Read(bs)
		if err != nil {
			break
		}

		reqs += 1
	}

	c <- reqs
}

func printUsage(arg int) {
	if arg > 0 {
		fmt.Fprintf(os.Stderr, "bad arg %d", arg);
	}
	fmt.Fprintf(os.Stderr, "usage:%s [#threads] [rip] [n] " +
		    "[measure_sec] [step_us] [end_us]", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) != 7 {
		printUsage(-1)
	}

	threads, err := strconv.Atoi(os.Args[1])
	if err != nil {
		printUsage(0)
	}

	uaddr, err := net.ResolveUDPAddr("udp4", os.Args[2] + ":8000")
	if err != nil {
		printUsage(1)
	}

	n, err := strconv.Atoi(os.Args[3])
	if err != nil {
		printUsage(2)
	}

	seconds, err := strconv.Atoi(os.Args[4])
	if err != nil {
		printUsage(4)
	}

	stepUS, err := strconv.Atoi(os.Args[5])
	if err != nil {
		printUsage(5)
	}

	endUS, err := strconv.Atoi(os.Args[6])
	if err != nil {
		printUsage(6)
	}

	callibrate(uint64(n))

	for curUS := 1; curUS <= endUS; curUS += stepUS {
		conns := make([]*net.UDPConn, threads)
		for i := 0; i < threads; i++ {
			conns[i], err = net.DialUDP("udp", nil, uaddr)
			if err != nil {
				os.Exit(1)
			}
		}

		// Launch a worker thread for reach connection.
		c := make(chan uint64, threads)
		start := time.Now() // start elapsed time measurement.
		for i := 0; i < threads; i++ {
			go worker(uint64(n * curUS), conns[i], c)
		}

		// Sleep for the experiment measurement duration.
		time.Sleep(time.Duration(seconds) * time.Second)

		// Close the UDP sockets.
		for i := 0; i < threads; i++ {
			conns[i].Close()
		}

		// Wait for all the threads to exit and sum total requests.
		reqs := uint64(0)
		for i := 0; i < threads; i++ {
			reqs += <-c
		}
		elapsed := time.Since(start) // stop elapsed time measurement.
		reqs_per_sec := float64(reqs) / elapsed.Seconds()
		ideal_reqs_per_sec := 8.0 * 1000000.0 / float64(curUS)
		fmt.Printf("%d %e %.4f\n", curUS, reqs_per_sec, reqs_per_sec / ideal_reqs_per_sec * 100)
	}
}
