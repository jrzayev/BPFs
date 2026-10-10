package main

import (
  "net/http"
  _ "net/http/pprof"
  "time"
  "fmt"
)

func cpuLoop() {
  x := 0
  for {
    x++
  }
}

func sleeper() {
  for {
    time.Sleep(time.Hour)
  }
}

func chanWaiter(ch chan int) {
  <-ch
}


func main() {
  fmt.Println("how are you buddy?...\n")
  go cpuLoop()
  go sleeper()
  go chanWaiter(make(chan int))

  http.ListenAndServe("localhost:8585", nil)
}
