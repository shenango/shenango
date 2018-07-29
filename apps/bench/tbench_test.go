package main

import (
	"testing"
	"sync"
	"runtime"
)

func BenchmarkSpawnJoin(b *testing.B) {
	c := make(chan int, 1)

	for i := 0; i < b.N; i++ {
		go func() {
			c <- 1
		}()
		<-c
	}
}

func BenchmarkUncontendedMutex(b *testing.B) {
	var m = &sync.Mutex{}

	for i := 0; i < b.N; i++ {
		m.Lock()
		m.Unlock()
	}
}

func BenchmarkYield(b *testing.B) {
	c := make(chan int, 1)

	go func() {
		for i := 0; i < b.N / 2; i++ {
			runtime.Gosched()
		}
		c <- 1
	}()

	for i := 0; i < b.N / 2; i++ {
		runtime.Gosched()
	}

	<-c
}

func BenchmarkCondvarPingPong(b *testing.B) {
	m := &sync.Mutex{}
	cv := sync.NewCond(m)
	c := make(chan int, 1)
	dir := bool(false)

	go func() {
		m.Lock()
		for i := 0; i < b.N / 2; i++ {
			for dir {
				cv.Wait()
			}
			dir = true
			cv.Signal()
		}
		m.Unlock()
		c <- 1
	}()

	m.Lock()
	for i := 0; i < b.N / 2; i++ {
		for !dir {
			cv.Wait()
		}
		dir = false
		cv.Signal()
	}
	m.Unlock()

	<-c
}
