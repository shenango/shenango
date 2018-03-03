package main

func work(c chan int) {
	c <- 1
}

func main() {
	c := make(chan int, 1)
	for i := 0; i < 100000000; i++ {
		go work(c)
		<-c
	}
}
