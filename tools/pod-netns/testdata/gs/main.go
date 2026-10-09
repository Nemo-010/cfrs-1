package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func main() {
	port, _ := strconv.Atoi(os.Args[1])

	// getsockname BEFORE any bind: the supervisor has not faked anything yet,
	// so this should notify and be answered from the kernel.
	{
		fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		var st syscall.RawSockaddrInet4
		l := uint32(unsafe.Sizeof(st))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKNAME, uintptr(fd),
			uintptr(unsafe.Pointer(&st)), uintptr(unsafe.Pointer(&l)), 0, 0, 0)
		fmt.Printf("PRE-BIND  getsockname(fd=%d) errno=%v\n", fd, e)
		syscall.Close(fd)
	}

	// now bind (this consumes the one allowed fake), then getsockname again
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	sa := &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	fmt.Printf("bind -> %v\n", syscall.Bind(fd, sa))
	got, gerr := syscall.Getsockname(fd)
	fmt.Printf("POST-BIND getsockname -> %v err=%v\n", got, gerr)
}
