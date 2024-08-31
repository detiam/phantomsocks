package phantomtcp

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ConnectionInfo struct {
	Link gopacket.LinkLayer
	IP   gopacket.NetworkLayer
	TCP  layers.TCP
}

type SynInfo struct {
	Number uint32
	Option uint32
}

var ConnSyn sync.Map
var ConnInfo4 [65536]chan *ConnectionInfo
var ConnInfo6 [65536]chan *ConnectionInfo
var TFOCookies sync.Map
var TFOPayload [64][]byte
var TFOSynID uint8 = 0

const domainBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

func IsAddressInUse(err error) bool {
	//return errors.Is(err, syscall.EADDRINUSE)
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	return false
}

func IsNormalError(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	switch e := errOpError.Err.(type) {
	case *os.SyscallError:
		errErrno, ok := e.Err.(syscall.Errno)
		if !ok {
			return false
		}

		if errErrno == syscall.ETIMEDOUT ||
			errErrno == syscall.ECONNREFUSED ||
			errErrno == syscall.ECONNRESET {
			return true
		}
	default:
		//logPrintln(2, reflect.TypeOf(e))
		return true
	}

	return false
}

func AddConn(synAddr string, option uint32) {
	result, ok := ConnSyn.LoadOrStore(synAddr, SynInfo{1, option})
	if ok {
		info := result.(SynInfo)
		info.Number++
		info.Option = option
		ConnSyn.Store(synAddr, info)
	}
}

func DelConn(synAddr string) {
	result, ok := ConnSyn.Load(synAddr)
	if ok {
		info := result.(SynInfo)
		if info.Number > 1 {
			info.Number--
			ConnSyn.Store(synAddr, info)
		} else {
			ConnSyn.Delete(synAddr)
		}
	}
}

func GetLocalAddr(name string, ipv6 bool) (*net.TCPAddr, error) {
	if name == "" {
		return nil, nil
	}

	inf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		localAddr, ok := addr.(*net.IPNet)
		if ok {
			var laddr *net.TCPAddr
			ip4 := localAddr.IP.To4()
			if ipv6 {
				if ip4 != nil || localAddr.IP[0]&0xfc == 0xfc {
					continue
				}
				ip := make([]byte, 16)
				copy(ip[:16], localAddr.IP)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			} else {
				if ip4 == nil {
					continue
				}
				ip := make([]byte, 4)
				copy(ip[:4], ip4)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			}

			return laddr, nil
		}
	}

	return nil, nil
}

func (pface *PhantomInterface) Dial(host string, port int, b []byte) (net.Conn, *ConnectionInfo, error) {
	connect_err := errors.New("connection does not exist")
	raddrs, err := pface.GetRemoteAddresses(host, port)
	if err != nil || raddrs == nil {
		return nil, nil, err
	}

	var conn net.Conn
	device := pface.Device
	hint := pface.Hint

	if hint&HINT_MODIFY == 0 {
		raddr := raddrs[mathrand.Intn(len(raddrs))]
		var laddr *net.TCPAddr = nil
		if device != "" {
			laddr, err = GetLocalAddr(device, raddr.IP.To4() == nil)
			if err != nil {
				return nil, nil, err
			}
		}

		conn, err = net.DialTCP("tcp", laddr, raddr)
		if err == nil {
			if pface.Protocol != 0 {
				err = pface.ProxyHandshake(conn, nil, host, port)
				if err != nil {
					conn.Close()
					return nil, nil, err
				}
			}

			if b != nil {
				_, err = conn.Write(b)
			}
		}

		return conn, nil, err
	} else {
		offset := 0
		length := 0

		if b != nil {
			if hint&HINT_TFO != 0 {
				length = len(b)
			} else {
				if b[0] == 0x16 {
					offset, length, _ = GetSNI(b)
				} else {
					offset, length = GetHost(b)
				}
			}
		}

		send_magic_packet := func(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
			var mss uint32 = 1220
			var segment uint32 = 0
			var totalLen uint32 = uint32(len(payload))
			initSeq := connInfo.TCP.Seq
			for totalLen-segment > 1220 {
				err := ModifyAndSendPacket(connInfo, payload[segment:segment+mss], hint, ttl, count)
				if err != nil {
					return err
				}
				segment += mss
				connInfo.TCP.Seq += mss
				time.Sleep(10 * time.Millisecond)
			}
			err = ModifyAndSendPacket(connInfo, payload[segment:], hint, ttl, count)
			connInfo.TCP.Seq = initSeq
			time.Sleep(10 * time.Millisecond)
			return err
		}

		if PassiveMode {
			raddr := raddrs[mathrand.Intn(len(raddrs))]

			var laddr *net.TCPAddr = nil
			if device != "" {
				laddr, err = GetLocalAddr(device, raddr.IP.To4() == nil)
				if err != nil {
					return nil, nil, err
				}
			}

			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err == nil && pface.Protocol != 0 {
				err = pface.ProxyHandshake(conn, nil, host, port)
			}

			if err == nil && b != nil {
				if length > 0 {
					cut := offset + length/2
					tos := 1 << 2
					if hint&HINT_TTL != 0 {
						tos = int(pface.TTL) << 2
					}
					if SendWithOption(conn, b[:cut], tos, 1) == nil {
						_, err = conn.Write(b[cut:])
					}
				} else {
					_, err = conn.Write(b)
				}
			}

			if err != nil {
				conn.Close()
				return nil, nil, err
			}

			return conn, nil, err
		} else {
			if offset == 0 {
				length = len(b)
				hint |= HINT_RAND
			}

			fakepaylen := len(b)
			fakepayload := make([]byte, fakepaylen)
			copy(fakepayload, b[:fakepaylen])

			cut := offset + length/2
			var tfo_payload []byte = nil
			if (hint & (HINT_TFO | HINT_HTFO)) != 0 {
				if (hint & HINT_TFO) != 0 {
					tfo_payload = b
				} else {
					tfo_payload = b[:cut]
				}
			} else if hint&HINT_RAND != 0 {
				_, err = rand.Read(fakepayload)
				if err != nil {
					logPrintln(1, err)
				}
			} else {
				min_dot := offset + length
				max_dot := offset
				for i := offset; i < offset+length; i++ {
					if fakepayload[i] == '.' {
						if i < min_dot {
							min_dot = i
						}
						if i > max_dot {
							max_dot = i
						}
					} else {
						fakepayload[i] = domainBytes[mathrand.Intn(len(domainBytes))]
					}
				}
				if min_dot == max_dot {
					min_dot = offset
				}

				cut = (min_dot + max_dot) / 2
			}

			var synpacket *ConnectionInfo
			var preferaddrs, fallbackaddrs []*net.TCPAddr
			for _, addr := range raddrs {
				switch {
				case hint&HINT_IPV4 == 0 && hint&HINT_IPV6 == 0: // prefer IPv4
					if addr.IP.To4() != nil {
						preferaddrs = append(preferaddrs, addr)
					} else {
						fallbackaddrs = append(fallbackaddrs, addr)
					}
				case hint&HINT_IPV4 != 0 && hint&HINT_IPV6 != 0: // prefer IPv6
					if addr.IP.To4() == nil {
						preferaddrs = append(preferaddrs, addr)
					} else {
						fallbackaddrs = append(fallbackaddrs, addr)
					}
				default:
					preferaddrs = append(preferaddrs, addr)
				}
			}

			type DailResult struct {
				conn      net.Conn
				synpacket *ConnectionInfo
				err       error
			}

			synpacket2chan := func(addrs []*net.TCPAddr, channel chan DailResult) {
				if addrs == nil {
					channel <- DailResult{err: errors.New("no addrs?")}
					return
				}
				for _, addr := range addrs {
					laddr, err := GetLocalAddr(device, addr.IP.To4() == nil)
					if err != nil {
						channel <- DailResult{err: errors.New("invalid device")}
						return
					}

					conn, synpacket, err := DialConnInfo(laddr, addr, pface, tfo_payload)
					if err != nil {
						if IsNormalError(err) {
							continue
						}
						channel <- DailResult{err: err}
						return
					}

					channel <- DailResult{conn: conn, synpacket: synpacket, err: err}
					return
				}
				channel <- DailResult{err: connect_err}
			}

			synpchan := make(chan DailResult, 2)
			if len(preferaddrs) > 0 {
				go synpacket2chan(preferaddrs, synpchan)
			} else {
				go synpacket2chan(fallbackaddrs, synpchan)
			}
			select {
			case result := <-synpchan:
				if result.err != nil {
					return nil, nil, result.err
				}
				conn = result.conn
				synpacket = result.synpacket
			case <-time.After(300 * time.Millisecond):
				if len(fallbackaddrs) > 0 && len(preferaddrs) > 0 {
					go synpacket2chan(fallbackaddrs, synpchan)
				}
				result := <-synpchan
				if result.err != nil {
					return nil, nil, result.err
				}
				conn = result.conn
				synpacket = result.synpacket
			}

			if synpacket == nil {
				if conn != nil {
					conn.Close()
				}
				return nil, nil, connect_err
			}

			logPrintln(3, host, conn.RemoteAddr(), "connected")

			if (hint & HINT_DELAY) != 0 {
				time.Sleep(time.Second)
			}

			synpacket.TCP.Seq++

			if pface.Protocol != 0 {
				err = pface.ProxyHandshake(conn, synpacket, host, port)
				if err != nil {
					conn.Close()
					return nil, nil, err
				}
				if pface.Protocol == HTTPS {
					conn.Write(b)
					return conn, synpacket, nil
				}
			}

			count := 1
			if (hint & (HINT_TFO | HINT_HTFO)) != 0 {
				if (hint & HINT_HTFO) != 0 {
					_, err = conn.Write(b[cut:])
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
				}
				synpacket.TCP.Seq += uint32(len(b))
			} else {
				if hint&HINT_MODE2 != 0 {
					synpacket.TCP.Seq += uint32(cut)
					fakepayload = fakepayload[cut:]
					count = 2
				} else {
					err = send_magic_packet(synpacket, fakepayload, hint, pface.TTL, count)
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
				}

				SegOffset := 0
				if hint&(HINT_SSEG|HINT_1SEG) != 0 {
					if hint&HINT_1SEG != 0 {
						SegOffset = 1
					} else {
						SegOffset = 4
					}
					_, err = conn.Write(b[:SegOffset])
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
				}

				_, err = conn.Write(b[SegOffset:cut])
				if err != nil {
					conn.Close()
					return nil, nil, err
				}

				err = send_magic_packet(synpacket, fakepayload, hint, pface.TTL, count)
				if err != nil {
					conn.Close()
					return nil, nil, err
				}

				_, err = conn.Write(b[cut:])
				if err != nil {
					conn.Close()
					return nil, nil, err
				}

				synpacket.TCP.Seq += uint32(len(b))
				if hint&HINT_SAT != 0 {
					_, err = rand.Read(fakepayload)
					if err != nil {
						conn.Close()
						return nil, nil, err
					}
					err = send_magic_packet(synpacket, fakepayload, hint, pface.TTL, 2)
				}
			}

			return conn, synpacket, err
		}
	}
}

func (server *PhantomInterface) Keep(client, conn net.Conn, connInfo *ConnectionInfo) {
	fakepayload := make([]byte, 1500)

	go func() {
		var b [1460]byte
		for {
			n, err := client.Read(b[:])
			if err != nil {
				conn.Close()
				return
			}

			err = ModifyAndSendPacket(connInfo, fakepayload, server.Hint, server.TTL, 2)
			if err != nil {
				conn.Close()
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				conn.Close()
				return
			}
			connInfo.TCP.Seq += uint32(n)
		}
	}()

	io.Copy(client, conn)
}

func (server *PhantomInterface) GetRemoteAddresses(host string, port int) ([]*net.TCPAddr, error) {
	switch server.Protocol {
	case DIRECT:
		return server.ResolveTCPAddrs(host, port)
	case REDIRECT:
		if server.Address != "" {
			var str_port string
			var err error
			host, str_port, err = net.SplitHostPort(server.Address)
			if err != nil {
				return nil, err
			}
			port, err = strconv.Atoi(str_port)
			if err != nil {
				return nil, err
			}
		}
		return server.ResolveTCPAddrs(host, port)
	case NAT64:
		addrs, err := server.ResolveTCPAddrs(host, port)
		if err != nil {
			return nil, err
		}
		tcpAddrs := make([]*net.TCPAddr, len(addrs))
		for i, addr := range addrs {
			proxy := server.Address + addr.IP.String()
			tcpAddrs[i] = &net.TCPAddr{IP: net.ParseIP(proxy), Port: port}
		}
		return tcpAddrs, nil
	default:
		host, str_port, err := net.SplitHostPort(server.Address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(str_port)
		if err != nil {
			return nil, err
		}
		return server.ResolveTCPAddrs(host, port)
	}
}

func (pface *PhantomInterface) ProxyHandshake(conn net.Conn, synpacket *ConnectionInfo, host string, port int) error {
	var err error
	proxy_err := errors.New("invalid proxy")

	hint := pface.Hint & HINT_MODIFY
	var proxy_seq uint32 = 0
	switch pface.Protocol {
	case REDIRECT:
	case NAT64:
	case HTTP:
		{
			header := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
			if pface.Authorization != nil {
				header += fmt.Sprintf("Authorization: Basic %s\r\n", base64.RawURLEncoding.EncodeToString(pface.Authorization))
			}
			header += "\r\n"
			request := []byte(header)
			fakepayload := make([]byte, len(request))
			var n int = 0
			if synpacket != nil {
				if hint&HINT_SSEG != 0 {
					n, err = conn.Write(request[:4])
					if err != nil {
						return err
					}
				} else if hint&HINT_MODE2 != 0 {
					n, err = conn.Write(request[:10])
					if err != nil {
						return err
					}
				}

				proxy_seq += uint32(n)
				err = ModifyAndSendPacket(synpacket, fakepayload, hint, pface.TTL, 2)
				if err != nil {
					return err
				}

				if hint&HINT_SSEG != 0 {
					n, err = conn.Write(request[4:])
				} else if hint&HINT_MODE2 != 0 {
					n, err = conn.Write(request[10:])
				} else {
					n, err = conn.Write(request)
				}
				if err != nil {
					return err
				}
				proxy_seq += uint32(n)
			} else {
				n, err = conn.Write(request)
				if err != nil || n == 0 {
					return err
				}
			}
			var response [128]byte
			n, err = conn.Read(response[:])
			if err != nil || !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
				return errors.New("failed to connect to proxy")
			}
		}
	case HTTPS:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, pface.TTL, 2)
				if err != nil {
					return err
				}
			}
			conf := &tls.Config{
				InsecureSkipVerify: true,
			}
			conn = tls.Client(conn, conf)
			header := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
			if pface.Authorization != nil {
				header += fmt.Sprintf("Authorization: Basic %s\r\n", base64.RawURLEncoding.EncodeToString(pface.Authorization))
			}
			header += "\r\n"
			request := []byte(header)
			n, err := conn.Write(request)
			if err != nil || n == 0 {
				return err
			}
			var response [128]byte
			n, err = conn.Read(response[:])
			if err != nil || !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
				return errors.New("failed to connect to proxy")
			}
		}
	case SOCKS4:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, pface.TTL, 2)
				if err != nil {
					return err
				}
			}

			copy(b[:], []byte{0x04, 0x01})
			binary.BigEndian.PutUint16(b[2:], uint16(port))

			requestLen := 0
			ip := net.ParseIP(host).To4()
			if ip != nil {
				copy(b[4:], ip[:4])
				b[8] = 0
				requestLen = 9
			} else {
				copy(b[4:], []byte{0, 0, 0, 1, 0})
				copy(b[9:], []byte(host))
				requestLen = 9 + len(host)
				b[requestLen] = 0
				requestLen++
			}
			n, err := conn.Write(b[:requestLen])
			if err != nil {
				return err
			}
			proxy_seq += uint32(n)
			n, err = conn.Read(b[:8])
			if err != nil {
				return err
			}
			if n < 8 || b[0] != 0 || b[1] != 90 {
				return proxy_err
			}
		}
	case SOCKS5:
		{
			var b [264]byte
			if synpacket != nil {
				err := ModifyAndSendPacket(synpacket, b[:], hint, pface.TTL, 2)
				if err != nil {
					return err
				}
			}

			n, err := conn.Write([]byte{0x05, 0x01, 0x00})
			if err != nil {
				return err
			}
			proxy_seq += uint32(n)
			_, err = conn.Read(b[:])
			if err != nil {
				return err
			}

			if b[0] != 0x05 {
				return proxy_err
			}

			if pface.DNS != "" {
				_, ips := NSLookup(host, pface.Hint, pface.DNS)
				if ips != nil {
					ip := ips[mathrand.Intn(len(ips))]
					ip4 := ip.To4()
					if ip4 != nil {
						copy(b[:], []byte{0x05, 0x01, 0x00, 0x01})
						copy(b[4:], ip4[:4])
						binary.BigEndian.PutUint16(b[8:], uint16(port))
						n, err = conn.Write(b[:10])
					} else {
						copy(b[:], []byte{0x05, 0x01, 0x00, 0x04})
						copy(b[4:], ip[:16])
						binary.BigEndian.PutUint16(b[20:], uint16(port))
						n, err = conn.Write(b[:22])
					}
					host = ""
				}
			}

			if host != "" {
				copy(b[:], []byte{0x05, 0x01, 0x00, 0x03})
				hostLen := len(host)
				b[4] = byte(hostLen)
				copy(b[5:], []byte(host))
				binary.BigEndian.PutUint16(b[5+hostLen:], uint16(port))
				n, err = conn.Write(b[:7+hostLen])
			}

			if err != nil {
				return err
			}

			proxy_seq += uint32(n)

			n, err = conn.Read(b[:])
			if err != nil {
				return err
			}
			if n < 2 || b[0] != 0x05 || b[1] != 0x00 {
				return proxy_err
			}
		}
	default:
		return proxy_err
	}

	if synpacket != nil {
		synpacket.TCP.Seq += proxy_seq
	}

	return nil
}

func relay(left, right net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}
