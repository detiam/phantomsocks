package proxy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"syscall"
	"time"
)

var SystemProxy string = ""

func SetProxy(dev, address string, state bool) error {
	u, err := url.Parse(address)
	if err != nil {
		return err
	}

	if state {
		SystemProxy = address
		switch u.Scheme {
		case "dns":
			go func(nameserver, path string) {
				resolv_content := []byte("nameserver " + nameserver)
				for SystemProxy != "" {
					content, err := ioutil.ReadFile(path)
					if err == nil && !bytes.Equal(content, resolv_content) {
						ioutil.WriteFile(path, resolv_content, 0644)
					}
					time.Sleep(time.Second * 10)
				}
			}(u.Host, u.Path)
		}
	} else {
		SystemProxy = ""
	}

	return nil
}

func SetKeepAlive(conn net.Conn) error {
	f, err := conn.(*net.TCPConn).File()
	defer f.Close()
	if err == nil {
		fd := int(f.Fd())
		err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		if err != nil {
			return err
		}
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10)
		if err != nil {
			return err
		}
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
		if err != nil {
			return err
		}
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 5)
		if err != nil {
			return err
		}
	}
	return nil
}

func InstallService() {
	fmt.Println("Unsupported Platform.")
}

func RemoveService() {
	fmt.Println("Unsupported Platform.")
}

func StartService() {
	fmt.Println("Unsupported Platform.")
}

func StopService() {
	fmt.Println("Unsupported Platform.")
}

func RunAsService(start func()) bool {
	return false
}
