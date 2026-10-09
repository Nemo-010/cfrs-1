// A statically linked child fixture.
//
// Statically linked on purpose: it is the case an LD_PRELOAD shim cannot reach,
// so a pass here is evidence that pod-netns needs no loader. It binds an
// AF_INET address the cage refuses, then asks the kernel what address it holds,
// which exercises the supervisor's virtual-address table.
//
// It also connects to the AF_UNIX socket named by POD_NETNS_UNIX and writes to
// it, to show the proxied path carries bytes, then exits. The read after the
// write is bounded by SO_RCVTIMEO, because nobody is obliged to answer and the
// fixture must terminate on its own rather than hang the test harness.

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
)

func main() {
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("usage: sg PORT")
		os.Exit(2)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("socket:", err)
		os.Exit(1)
	}
	fmt.Printf("socket fd=%d err=%v\n", fd, err)

	sa := &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	berr := syscall.Bind(fd, sa)
	fmt.Printf("bind &{%d [127 0 0 1] ...} -> %v\n", port, berr)

	got, gerr := syscall.Getsockname(fd)
	fmt.Printf("getsockname(same fd %d) -> %v err=%v\n", fd, got, gerr)

	lerr := syscall.Listen(fd, 4)
	fmt.Printf("listen -> %v\n", lerr)

	if path := os.Getenv("POD_NETNS_UNIX"); path != "" {
		c, cerr := dialUnix(path)
		if cerr != nil {
			fmt.Printf("unix connect: %v\n", cerr)
		} else {
			fmt.Printf("unix connect: OK fd=%d\n", c)
			payload := []byte("GET / HTTP/1.0\r\n\r\n")
			n, werr := syscall.Write(c, payload)
			fmt.Printf("wrote %d bytes (%v)\n", n, werr)

			tv := syscall.NsecToTimeval(int64(2 * time.Second))
			if err := syscall.SetsockoptTimeval(c, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err == nil {
				buf := make([]byte, 256)
				rn, rerr := syscall.Read(c, buf)
				// A timed-out read returns -1; slicing with that index panics.
				if rn > 0 {
					fmt.Printf("read %d bytes (%v): %q\n", rn, rerr, string(buf[:rn]))
				} else {
					fmt.Printf("read returned %d (%v); no reply, as expected\n", rn, rerr)
				}
			}
			syscall.Close(c)
		}
	}
}

func dialUnix(path string) (int, error) {
	c, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}
	if err := syscall.Connect(c, &syscall.SockaddrUnix{Name: path}); err != nil {
		syscall.Close(c)
		return -1, err
	}
	return c, nil
}
