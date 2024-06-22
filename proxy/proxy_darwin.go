package proxy

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
)

func RunCmd(cmd *exec.Cmd, arg ...string) (string, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	defer stdout.Close()

	if err := cmd.Start(); err != nil {
		return "", err
	}

	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", err
	} else {
		return string(opBytes), nil
	}
}

func SetProxy(dev, proxy string, state bool) error {
	cmd := exec.Command("networksetup", "-listnetworkserviceorder")
	out, err := RunCmd(cmd)
	if err != nil {
		return err
	}

	u, err := url.Parse(proxy)
	if err != nil {
		return err
	}

	proxyProtocol := ""
	proxyState := ""

	switch u.Scheme {
	case "http":
		proxyProtocol = "-setwebproxy"
		proxyState = "-setwebproxystate"
	case "socks":
		proxyProtocol = "-setsocksfirewallproxy"
		proxyState = "-setsocksfirewallproxystate"
	case "dns":
		proxyProtocol = "-setdnsservers"
	default:
		return nil
	}

	name := ""
	for _, networkservice := range strings.Split(out, "\n\n") {
		lines := strings.Split(networkservice, "\n")
		linesLen := len(lines)
		if linesLen < 2 {
			continue
		}

		name = lines[linesLen-2][4:]
		_en := strings.Split(lines[linesLen-1], " ")
		en := _en[len(_en)-1]
		en = en[:len(en)-1]

		if dev == en {
			break
		}
	}

	if state {
		if proxyState == "" {
			cmd = exec.Command("networksetup", proxyProtocol, name, u.Host)
			if err := cmd.Start(); err != nil {
				return err
			}
		} else {
			addr, err := net.ResolveTCPAddr("tcp", u.Host)
			if err != nil {
				return err
			}

			cmd = exec.Command("networksetup", proxyProtocol, name, addr.IP.String(), strconv.Itoa(addr.Port))
			if err := cmd.Start(); err != nil {
				return err
			}
			cmd = exec.Command("networksetup", proxyState, name, "on")
			if err := cmd.Start(); err != nil {
				return err
			}
		}
	} else {
		if proxyState == "" {
			cmd := exec.Command("networksetup", proxyProtocol, name, "empty")
			if err := cmd.Start(); err != nil {
				return err
			}
		} else {
			cmd := exec.Command("networksetup", proxyState, name, "off")
			if err := cmd.Start(); err != nil {
				return err
			}
		}
	}

	return nil
}

func SetKeepAlive(conn net.Conn) error {
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
