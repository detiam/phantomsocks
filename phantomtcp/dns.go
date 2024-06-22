package phantomtcp

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RecordAddresses struct {
	TTL       int64
	Addresses []net.IP
}

type DNSRecords struct {
	Index    uint32
	ALPN     uint32
	IPv4Hint *RecordAddresses
	IPv6Hint *RecordAddresses
	Domains  []string
	Ech      []byte
}

var DNSMinTTL uint32 = 0
var VirtualAddrPrefix byte = 255
var DNSCache sync.Map
var Nose []string = []string{"phantom.socks"}
var NoseLock sync.Mutex
var NSLookupLock sync.Mutex

func TCPlookup(request []byte, address string, server *PhantomInterface) ([]byte, error) {
	data := make([]byte, 1024)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	var conn net.Conn
	var err error = nil
	if server != nil {
		host, port := splitHostPort(address)
		conn, _, err = server.Dial(host, port, data[:len(request)+2])
		if err != nil {
			return nil, err
		}
	} else {
		conn, err = net.DialTimeout("tcp", address, time.Second*5)
		if err != nil {
			return nil, err
		}

		_, err = conn.Write(data[:len(request)+2])
		if err != nil {
			conn.Close()
			return nil, err
		}
	}
	defer conn.Close()

	n, err := conn.Read(data)
	if err != nil || n < 2 {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(data[:2]) + 2)
	recvlen := n
	for recvlen < length && n > 0 {
		n, err = conn.Read(data[recvlen:])
		if err != nil {
			return nil, err
		}
		recvlen += n
	}
	return data[2:recvlen], nil
}

func TCPlookupDNS64(request []byte, address string, offset int, prefix []byte) ([]byte, error) {
	response6 := make([]byte, 1024)
	offset6 := offset
	offset4 := offset

	binary.BigEndian.PutUint16(request[offset-4:offset-2], 1)
	response, err := TCPlookup(request, address, nil)
	if err != nil {
		return nil, err
	}

	copy(response6, response[:offset])
	binary.BigEndian.PutUint16(response6[offset-4:offset-2], 28)

	count := int(binary.BigEndian.Uint16(response[6:8]))
	for i := 0; i < count; i++ {
		for {
			if offset >= len(response) {
				log.Println(offset)
				return nil, nil
			}
			length := response[offset]
			offset++
			if length == 0 {
				break
			}
			if length < 63 {
				offset += int(length)
				if offset+2 > len(response) {
					log.Println(offset)
					return nil, nil
				}
			} else {
				offset++
				break
			}
		}
		if offset+2 > len(response) {
			log.Println(offset)
			return nil, nil
		}

		copy(response6[offset6:], response[offset4:offset])
		offset6 += offset - offset4
		offset4 = offset

		AType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		if offset+2 > len(response) {
			log.Println(offset)
			return nil, nil
		}
		DataLength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		offset += int(DataLength)
		if AType == 1 {
			if offset > len(response) {
				log.Println(offset)
				return nil, nil
			}
			binary.BigEndian.PutUint16(response6[offset6:], 28)
			offset6 += 2
			offset4 += 2
			copy(response6[offset6:], response[offset4:offset4+6])
			offset6 += 6
			offset4 += 6
			binary.BigEndian.PutUint16(response6[offset6:], DataLength+12)
			offset6 += 2
			offset4 += 2

			copy(response6[offset6:], prefix[:12])
			offset6 += 12
			copy(response6[offset6:], response[offset4:offset])
			offset6 += offset - offset4
			offset4 = offset
		} else {
			copy(response6[offset6:], response[offset4:offset])
			offset6 += offset - offset4
			offset4 = offset
		}
	}

	return response6[:offset6], nil
}

func UDPlookup(request []byte, address string) ([]byte, error) {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_, err = conn.Write(request)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	response := make([]byte, 1024)

	if request[11] == 0 {
		n, err := conn.Read(response[:])
		return response[:n], err
	} else {
		var n int
		for {
			n, err = conn.Read(response[:])
			if err != nil {
				return nil, err
			}

			if request[11] == 0 || response[11] > 0 {
				break
			}
		}
		return response[:n], nil
	}
}

func TLSlookup(request []byte, address string) ([]byte, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	data := make([]byte, 1024)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	_, err = conn.Write(data[:len(request)+2])
	if err != nil {
		return nil, err
	}

	n, err := conn.Read(data)
	if err != nil || n < 2 {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(data[:2]) + 2)
	recvlen := n
	for recvlen < length && n > 0 {
		n, err = conn.Read(data[recvlen:])
		if err != nil {
			return nil, err
		}
		recvlen += n
	}
	return data[2:recvlen], nil
}

func HTTPSlookup(request []byte, u *url.URL, domain string) ([]byte, error) {
	address := u.Host
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "443"
		address += ":443"
	}

	if domain == "" {
		domain = host
	}
	path := u.Path
	if port != "443" {
		host = address
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	}
	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	httpRequest := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", path, host, len(request))
	logPrintln(5, httpRequest)
	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(request)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 2048)
	recvlen := 0
	headerLen := 0
	contentLength := 0
	for {
		n, err := conn.Read(data[recvlen:])
		recvlen += n

		if recvlen > 0 {
			if contentLength == 0 {
				offset := bytes.Index(data[:recvlen], []byte("\r\n\r\n"))
				if offset != -1 {
					headerLen = offset + 4
					header := string(data[:headerLen])
					logPrintln(5, header)
					for _, line := range strings.Split(header, "\r\n") {
						field := strings.SplitN(line, ": ", 2)
						if len(field) > 1 {
							if field[0] == "Content-Length" {
								contentLength, err = strconv.Atoi(field[1])
								continue
							}
						}
					}
				}
			}

			if (recvlen - headerLen) >= contentLength {
				return data[headerLen : headerLen+contentLength], nil
			}
		}

		if err != nil || n == 0 {
			return nil, err
		}
	}
}

func TFOlookup(request []byte, address string) ([]byte, error) {
	data := make([]byte, 1024)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	var conn net.Conn
	var err error = nil

	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	conn, _, err = DialConnInfo(
		nil, addr,
		&PhantomInterface{
			Hint: HINT_TFO,
			TTL:  1,
		},
		data[:len(request)+2],
	)
	if err != nil {
		return nil, err
	}

	n, err := conn.Read(data)
	if err != nil || n < 2 {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(data[:2]) + 2)
	recvlen := n
	for recvlen < length && n > 0 {
		n, err = conn.Read(data[recvlen:])
		if err != nil {
			return nil, err
		}
		recvlen += n
	}
	return data[2:recvlen], nil
}

func GetQName(buf []byte) (string, int, int) {
	bufflen := len(buf)
	if bufflen < 13 {
		return "", 0, 0
	}
	length := buf[12]
	off := 13
	end := off + int(length)
	qname := string(buf[off:end])
	off = end

	for {
		if off >= bufflen {
			return "", 0, 0
		}
		length := buf[off]
		off++
		if length == 0x00 {
			break
		}
		end := off + int(length)
		if end > bufflen {
			return "", 0, 0
		}
		qname += "." + string(buf[off:end])
		off = end
	}
	end = off + 4
	if end > bufflen {
		return "", 0, 0
	}

	qtype := int(binary.BigEndian.Uint16(buf[off : off+2]))

	return qname, qtype, end
}

func GetName(buf []byte, offset int) (string, int) {
	name := ""
	for {
		length := int(buf[offset])
		offset++
		if length == 0 {
			break
		}
		if name != "" {
			name += "."
		}
		if length < 63 {
			name += string(buf[offset : offset+length])
			offset += int(length)
			if offset+2 > len(buf) {
				return "", offset
			}
		} else {
			_offset := int(buf[offset])
			_name, _ := GetName(buf, _offset)
			name += _name
			return name, offset + 1
		}
	}
	return name, offset
}

func GetNameOffset(response []byte, offset int) int {
	responseLen := len(response)

	for {
		if offset >= responseLen {
			return 0
		}
		length := response[offset]
		offset++
		if length == 0 {
			break
		}
		if length < 63 {
			offset += int(length)
			if offset+2 > responseLen {
				return 0
			}
		} else {
			offset++
			break
		}
	}

	return offset
}

func (records *DNSRecords) GetAnswers(response []byte, options ServerOptions) {
	nsfilter := func(address net.IP) net.IP {
		if options.BadSubnet != nil {
			if options.BadSubnet.Contains(address) {
				logPrintln(4, address, "bad address")
				return nil
			}
		}

		if options.PD != "" {
			address = net.ParseIP(options.PD + address.String())
		}

		return address
	}

	responseLen := len(response)

	offset := 12
	if offset > responseLen {
		return
	}

	QDCount := int(binary.BigEndian.Uint16(response[4:6]))
	ANCount := int(binary.BigEndian.Uint16(response[6:8]))

	if ANCount == 0 {
		return
	}

	for i := 0; i < QDCount; i++ {
		_offset := GetNameOffset(response, offset)
		if _offset == 0 {
			return
		}
		offset = _offset + 4
	}

	cname := ""
	for i := 0; i < ANCount; i++ {
		_offset := GetNameOffset(response, offset)
		if _offset == 0 {
			return
		}
		offset = _offset
		if offset+2 > responseLen {
			return
		}
		AType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 4
		if offset+4 > responseLen {
			return
		}
		TTL := binary.BigEndian.Uint32(response[offset : offset+4])
		if TTL < DNSMinTTL {
			TTL = DNSMinTTL
		}

		offset += 4
		if offset+2 > responseLen {
			return
		}
		DataLength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		switch AType {
		case 1:
			if offset+4 > responseLen {
				return
			}
			data := response[offset : offset+4]
			ip := net.IPv4(data[0], data[1], data[2], data[3])
			ip = nsfilter(ip).To4()
			if ip == nil {
				continue
			}
			if records.IPv4Hint == nil {
				records.IPv4Hint = &RecordAddresses{int64(TTL) + time.Now().Unix(), []net.IP{ip}}
			} else {
				records.IPv4Hint.Addresses = append(records.IPv4Hint.Addresses, ip)
			}
		case 28:
			var data [16]byte
			if offset+16 > responseLen {
				return
			}
			copy(data[:], response[offset:offset+16])
			ip := net.IP(response[offset : offset+16])
			ip = nsfilter(ip)
			if ip == nil {
				continue
			}
			if records.IPv6Hint == nil {
				records.IPv6Hint = &RecordAddresses{int64(TTL) + time.Now().Unix(), []net.IP{ip}}
			} else {
				records.IPv6Hint.Addresses = append(records.IPv6Hint.Addresses, ip)
			}
		case 65:
			offset += 3
			for offset+4 < responseLen {
				SvcParamKey := binary.BigEndian.Uint16(response[offset : offset+2])
				offset += 2
				SvcParamLen := int(binary.BigEndian.Uint16(response[offset : offset+2]))
				offset += 2
				SvcParamEnd := offset + SvcParamLen
				if SvcParamEnd > responseLen {
					break
				}
				records.ALPN |= HINT_ALPN
				switch SvcParamKey {
				case 1:
					for offset+1 < SvcParamEnd {
						ALPNLen := int(response[offset])
						offset++
						if offset+ALPNLen > SvcParamEnd {
							break
						}
						ALPN := string(response[offset : offset+ALPNLen])
						offset += ALPNLen
						switch ALPN {
						case "http/1.1":
							records.ALPN |= HINT_HTTP
						case "h2":
							records.ALPN |= HINT_HTTPS
						case "h3":
							records.ALPN |= HINT_HTTP3
						}
					}
				case 4:
					var IPv4Hint []net.IP
					for offset < SvcParamEnd {
						data := response[offset : offset+4]
						IPv4Hint = append(IPv4Hint, net.IPv4(data[0], data[1], data[2], data[3]))
						offset += 4
					}
					records.IPv4Hint = &RecordAddresses{int64(TTL) + time.Now().Unix(), IPv4Hint}
				case 5:
					records.Ech = make([]byte, SvcParamLen)
					copy(records.Ech, response[offset:SvcParamEnd])
				case 6:
					var IPv6Hint []net.IP
					for offset < SvcParamEnd {
						ip := net.IP(response[offset : offset+16])
						IPv6Hint = append(IPv6Hint, ip)
						offset += 16
					}
					records.IPv6Hint = &RecordAddresses{int64(TTL) + time.Now().Unix(), IPv6Hint}
				}
				offset = SvcParamEnd
			}
		case 5:
			cname, _ = GetName(response, offset)
			logPrintln(4, "CNAME:", cname)
		}

		offset += int(DataLength)
	}
}

func (records *DNSRecords) PackAnswers(qtype int, minttl uint32) (int, []byte) {
	packA := func(rec *RecordAddresses) (int, []byte) {
		var ttl uint32 = 0
		if rec.TTL > 0 {
			ttl = uint32(rec.TTL - time.Now().Unix())
		}
		if ttl < minttl {
			ttl = minttl
		}

		count := 0
		totalLen := 0
		for _, ip := range rec.Addresses {
			ip4 := ip.To4()
			if ip4 != nil {
				count++
				totalLen += 16
			} else {
				count++
				totalLen += 28
			}
		}

		answers := make([]byte, totalLen)
		length := 0
		for _, ip := range rec.Addresses {
			ip4 := ip.To4()
			if ip4 != nil {
				copy(answers[length:], []byte{0xC0, 0x0C, 0x00, 1,
					0x00, 0x01})
				length += 6
				binary.BigEndian.PutUint32(answers[length:], ttl)
				length += 4
				copy(answers[length:], []byte{0x00, 0x04})
				length += 2
				copy(answers[length:], ip4)
				length += 4
			} else {
				copy(answers[length:], []byte{0xC0, 0x0C, 0x00, 28,
					0x00, 0x01})
				length += 6
				binary.BigEndian.PutUint32(answers[length:], ttl)
				length += 4
				copy(answers[length:], []byte{0x00, 0x10})
				length += 2
				copy(answers[length:], ip)
				length += 16
			}
		}

		return count, answers
	}

	switch qtype {
	case 1:
		if records.IPv4Hint == nil {
			return 0, nil
		}
		return packA(records.IPv4Hint)
	case 28:
		if records.IPv6Hint == nil {
			return 0, nil
		}
		return packA(records.IPv6Hint)
	case 65:
		var totalLen uint16 = 15

		if records.ALPN&(HINT_HTTPS|HINT_HTTP3) != 0 {
			totalLen += 4
			if records.ALPN&HINT_HTTP3 != 0 {
				totalLen += 3
			}
			if records.ALPN&HINT_HTTPS != 0 {
				totalLen += 3
			}
		}

		v4Count := 0
		if records.IPv4Hint != nil {
			v4Count = len(records.IPv4Hint.Addresses)
			if v4Count > 0 {
				totalLen += uint16(4 + v4Count*4)
			}
		}

		echoLen := len(records.Ech)
		if echoLen > 0 {
			totalLen += uint16(4 + echoLen)
		}

		v6Count := 0
		if records.IPv6Hint != nil {
			v6Count = len(records.IPv6Hint.Addresses)
			if v6Count > 0 {
				totalLen += uint16(4 + v6Count*16)
			}
		}

		if totalLen == 15 {
			return 0, nil
		}

		answers := make([]byte, totalLen)
		copy(answers, []byte{0xC0, 0x0C, 0x00, 65, 0x00, 0x01})
		binary.BigEndian.PutUint32(answers[6:], minttl)
		binary.BigEndian.PutUint16(answers[10:], totalLen-12)
		binary.BigEndian.PutUint16(answers[12:], 1)
		answers[14] = 0
		length := 15

		if records.ALPN&(HINT_HTTPS|HINT_HTTP3) != 0 {
			copy(answers[length:], []byte{0, 1, 0, 0})
			svcLenOffset := length + 2
			length += 4
			if records.ALPN&HINT_HTTP3 != 0 {
				copy(answers[length:], []byte{2, 0x68, 0x33})
				length += 3
			}
			if records.ALPN&HINT_HTTPS != 0 {
				copy(answers[length:], []byte{2, 0x68, 0x32})
				length += 3
			}
			binary.BigEndian.PutUint16(answers[svcLenOffset:], uint16(length-svcLenOffset-2))
		}

		if v4Count > 0 {
			copy(answers[length:], []byte{0, 4})
			length += 2
			binary.BigEndian.PutUint16(answers[length:], uint16(v4Count*4))
			length += 2
			for _, ip := range records.IPv4Hint.Addresses {
				ip4 := ip.To4()
				if ip4 == nil {
					logPrintln(1, ip, "not IPv4")
					return 0, nil
				}
				copy(answers[length:], ip4)
				length += 4
			}
		}

		if echoLen > 0 {
			copy(answers[length:], []byte{0, 5})
			length += 2
			binary.BigEndian.PutUint16(answers[length:], uint16(echoLen))
			length += 2
			copy(answers[length:], records.Ech)
			length += echoLen
		}

		if v6Count > 0 {
			copy(answers[length:], []byte{0, 6})
			length += 2
			binary.BigEndian.PutUint16(answers[length:], uint16(v6Count*16))
			length += 2
			for _, ip := range records.IPv6Hint.Addresses {
				copy(answers[length:], ip.To16())
				length += 16
			}
		}

		return 1, answers
	}

	return 0, nil
}

func (records DNSRecords) BuildResponse(request []byte, qtype int, minttl uint32) []byte {
	length := len(request)

	if records.Index > 0 {
		response := make([]byte, 512)
		copy(response, request)
		response[2] = 0x81
		response[3] = 0x80

		switch qtype {
		case 1:
			answer := []byte{0xC0, 0x0C, 0x00, 1,
				0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04,
				VirtualAddrPrefix, 0}
			copy(response[length:], answer)
			length += 14
			binary.BigEndian.PutUint16(response[length:], uint16(records.Index))
			length += 2
			binary.BigEndian.PutUint16(response[6:], 1)
		case 28:
			return response[:length]
			/*
				answer := []byte{0xC0, 0x0C, 0x00, 28,
					0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10,
					0x00, 0x64, 0xff, VirtualAddrPrefix, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00}
				copy(response[length:], answer)
				length += 24
				binary.BigEndian.PutUint32(response[length:], uint32(records.Index))
				length += 4
				binary.BigEndian.PutUint16(response[6:], 1)
			*/
		case 65:
			copy(response[length:], []byte{0xC0, 0x0C, 0x00, 65, 0, 1, 0, 0, 0, 16, 0, 0, 0, 1, 0})
			dataLenOffset := length + 10
			length += 15
			if records.ALPN&(HINT_HTTPS|HINT_HTTP3) != 0 {
				copy(response[length:], []byte{0, 1, 0, 0})
				svcLenOffset := length + 2
				length += 4
				if records.ALPN&HINT_HTTP3 != 0 {
					copy(response[length:], []byte{2, 0x68, 0x33})
					length += 3
					copy(response[length:], []byte{5, 0x68, 0x33, 0x2d, 0x32, 0x39})
					length += 6
				}
				if records.ALPN&HINT_HTTPS != 0 {
					copy(response[length:], []byte{2, 0x68, 0x32})
					length += 3
				}
				binary.BigEndian.PutUint16(response[svcLenOffset:], uint16(length-svcLenOffset-2))
			}
			copy(response[length:], []byte{0, 4, 0, 4, VirtualAddrPrefix, 0})
			length += 6
			binary.BigEndian.PutUint16(response[length:], uint16(records.Index))
			length += 2
			binary.BigEndian.PutUint16(response[6:], 1)
			binary.BigEndian.PutUint16(response[dataLenOffset:], uint16(length-dataLenOffset-2))
		}

		return response[:length]
	} else {
		count, answer := records.PackAnswers(qtype, minttl)
		response := make([]byte, length+len(answer))
		copy(response, request)
		response[2] = 0x81
		response[3] = 0x80

		if count > 0 {
			binary.BigEndian.PutUint16(response[6:], uint16(count))
			copy(response[length:], answer)
			length += len(answer)
		}

		return response[:length]
	}
}

func PackQName(name string) []byte {
	length := strings.Count(name, "")
	QName := make([]byte, length+1)
	copy(QName[1:], []byte(name))
	o, l := 0, 0
	for i := 1; i < length; i++ {
		if QName[i] == '.' {
			QName[o] = byte(l)
			l = 0
			o = i
		} else {
			l++
		}
	}
	QName[o] = byte(l)

	return QName
}

type ServerOptions struct {
	ECS       string
	Type      string
	PD        string
	Domain    string
	BadSubnet *net.IPNet
	Fallback  net.IP
}

func ParseOptions(options string) ServerOptions {
	opts := strings.Split(options, "&")
	var serverOpts ServerOptions
	for _, opt := range opts {
		key := strings.SplitN(opt, "=", 2)
		if len(key) > 1 {
			switch key[0] {
			case "ecs":
				serverOpts.ECS = key[1]
			case "pd":
				serverOpts.PD = key[1]
			case "type":
				serverOpts.Type = key[1]
			case "domain":
				serverOpts.Domain = key[1]
			case "badsubnet":
				_, serverOpts.BadSubnet, _ = net.ParseCIDR(key[1])
			case "fallback":
				serverOpts.Fallback = net.ParseIP(key[1])
			}
		}
	}

	return serverOpts
}

func PackRequest(name string, qtype uint16, id uint16, ecs string) []byte {
	Request := make([]byte, 512)

	binary.BigEndian.PutUint16(Request[:], id)      //ID
	binary.BigEndian.PutUint16(Request[2:], 0x0100) //Flag
	binary.BigEndian.PutUint16(Request[4:], 1)      //QDCount
	binary.BigEndian.PutUint16(Request[6:], 0)      //ANCount
	binary.BigEndian.PutUint16(Request[8:], 0)      //NSCount
	if ecs != "" {
		binary.BigEndian.PutUint16(Request[10:], 1) //ARCount
	} else {
		binary.BigEndian.PutUint16(Request[10:], 0) //ARCount
	}

	qname := PackQName(name)
	length := len(qname)
	copy(Request[12:], qname)
	length += 12
	binary.BigEndian.PutUint16(Request[length:], qtype)
	length += 2
	binary.BigEndian.PutUint16(Request[length:], 0x01) //QClass
	length += 2

	if ecs != "" {
		Request[length] = 0 //Name
		length++
		binary.BigEndian.PutUint16(Request[length:], 41) // Type
		length += 2
		binary.BigEndian.PutUint16(Request[length:], 4096) // UDP Payload
		length += 2
		Request[length] = 0 // Highter bits in extended RCCODE
		length++
		Request[length] = 0 // EDNS0 Version
		length++
		binary.BigEndian.PutUint16(Request[length:], 0x800) // Z
		length += 2

		ecsip := net.ParseIP(ecs)
		ecsip4 := ecsip.To4()
		if ecsip4 != nil {
			binary.BigEndian.PutUint16(Request[length:], 11) // Length
			length += 2
			binary.BigEndian.PutUint16(Request[length:], 8) // Option Code
			length += 2
			binary.BigEndian.PutUint16(Request[length:], 7) // Option Length
			length += 2
			binary.BigEndian.PutUint16(Request[length:], 1) // Family
			length += 2
			Request[length] = 24 // Source Netmask
			length++
			Request[length] = 0 // Scope Netmask
			length++
			copy(Request[length:], ecsip4[:3])
			length += 3
		} else {
			binary.BigEndian.PutUint16(Request[length:], 15) // Length
			length += 2
			binary.BigEndian.PutUint16(Request[length:], 8) // Option Code
			length += 2
			binary.BigEndian.PutUint16(Request[length:], 11) // Option Length
			length += 2
			binary.BigEndian.PutUint16(Request[length:], 2) // Family
			length += 2
			Request[length] = 56 // Source Netmask
			length++
			Request[length] = 0 // Scope Netmask
			length++
			copy(Request[length:], ecsip[:7])
			length += 7
		}
	}

	return Request[:length]
}

func LoadDNSCache(qname string) *DNSRecords {
	var ok bool
	var result interface{}
	result, ok = DNSCache.Load(qname)
	if ok {
		return result.(*DNSRecords)
	}

	return nil
}

func StoreDNSCache(qname string, record *DNSRecords) {
	DNSCache.Store(qname, record)
}

func GetIPCache(name string, qtype uint16, records *DNSRecords) []net.IP {
	switch qtype {
	case 1:
		if records.IPv4Hint != nil {
			logPrintln(4, "Cached:", name, qtype, records.IPv4Hint.Addresses)
			return records.IPv4Hint.Addresses
		}
	case 28:
		if records.IPv6Hint != nil {
			logPrintln(4, "Cached:", name, qtype, records.IPv6Hint.Addresses)
			return records.IPv6Hint.Addresses
		}
	}

	return nil
}

func GetIP(name string, qtype uint16, hint uint32, u *url.URL, records *DNSRecords) []net.IP {
	var request []byte
	var response []byte
	var err error

	var options ServerOptions
	if u.RawQuery != "" {
		options = ParseOptions(u.RawQuery)
	}

	if u.Host != "" {
		switch u.Scheme {
		case "udp":
			request = PackRequest(name, qtype, uint16(0), options.ECS)
			response, err = UDPlookup(request, u.Host)
		case "tcp":
			request = PackRequest(name, qtype, uint16(0), options.ECS)
			response, err = TCPlookup(request, u.Host, nil)
		case "tls":
			request = PackRequest(name, qtype, uint16(0), options.ECS)
			response, err = TLSlookup(request, u.Host)
		case "https":
			request = PackRequest(name, qtype, uint16(0), options.ECS)
			response, err = HTTPSlookup(request, u, options.Domain)
		case "tfo":
			request = PackRequest(name, qtype, uint16(0), options.ECS)
			response, err = TFOlookup(request, u.Host)
		default:
			NoseLock.Lock()
			records.Index = uint32(len(Nose))
			records.ALPN = hint & HINT_DNS
			Nose = append(Nose, name)
			NoseLock.Unlock()
			return nil
		}
	}
	if err != nil {
		logPrintln(1, err)
		return nil
	}

	records.GetAnswers(response, options)

	switch qtype {
	case 1:
		if records.IPv4Hint == nil && options.Fallback != nil {
			if options.Fallback.To4() != nil {
				logPrintln(4, "request:", name, "fallback", options.Fallback)
				records.IPv4Hint = &RecordAddresses{0, []net.IP{options.Fallback}}
			}
		}
		if records.IPv4Hint == nil {
			records.IPv4Hint = &RecordAddresses{0, []net.IP{}}
		}
		logPrintln(3, "GetIP:", name, qtype, records.IPv4Hint.Addresses)
		return records.IPv4Hint.Addresses
	case 28:
		if records.IPv6Hint == nil && options.Fallback != nil {
			if options.Fallback.To4() == nil {
				records.IPv6Hint = &RecordAddresses{0, []net.IP{options.Fallback}}
			}
		}
		if records.IPv6Hint == nil {
			records.IPv6Hint = &RecordAddresses{0, []net.IP{}}
		}
		logPrintln(3, "GetIP:", name, qtype, records.IPv6Hint.Addresses)
		return records.IPv6Hint.Addresses
	}

	return nil
}

func NSLookup(name string, hint uint32, server string) (uint32, []net.IP) {
	var address []net.IP
	var records = LoadDNSCache(name)

	if records == nil {
		records = new(DNSRecords)
		StoreDNSCache(name, records)

		offset := 0
		for i := 0; i < SubdomainDepth; i++ {
			off := strings.Index(name[offset:], ".")
			if off == -1 {
				break
			}
			offset += off
			top := LoadDNSCache(name[offset:])
			if top != nil {
				*records = *top
				break
			}

			offset++
		}
	}

	if records.Domains != nil {
		var wg sync.WaitGroup
		var ResolveFakeCNAME = func(FakeCNAME string) {
			defer wg.Done()
			logPrintln(3, "FAKECNAME:", name, "->", FakeCNAME)
			_, ips := NSLookup(FakeCNAME, hint, server)
			if len(ips) == 0 {
				logPrintln(1, errors.New("no such host: "+FakeCNAME))
			}
			address = append(address, ips...)
		}
		var domainNum = len(records.Domains)
		wg.Add(domainNum)
		for i := 0; i < domainNum; i++ {
			go ResolveFakeCNAME(records.Domains[i])
		}
		wg.Wait()
	} else {
		var ReadCache = func() {
			if hint&HINT_IPV4 == hint&HINT_IPV6 {
				address = append(GetIPCache(name, 1, records), GetIPCache(name, 28, records)...)
			} else if hint&HINT_IPV4 != 0 {
				address = GetIPCache(name, 1, records)
			} else if hint&HINT_IPV6 != 0 {
				address = GetIPCache(name, 28, records)
			}
		}

		ReadCache()
		if address == nil {
			defer logPrintln(5, "Unblock NSLookup:", name)
			defer NSLookupLock.Unlock()
			logPrintln(5, "Block NSLookup:", name)
			NSLookupLock.Lock()

			ReadCache() // reload after get ip
			if len(address) > 0 {
				return records.Index, address
			}

			u, err := url.Parse(server)
			if err != nil {
				logPrintln(1, err)
				return 0, nil
			}

			if records.Index == 0 && hint != 0 {
				NoseLock.Lock()
				records.Index = uint32(len(Nose))
				records.ALPN = hint & HINT_DNS
				Nose = append(Nose, name)
				NoseLock.Unlock()
			}

			if hint&HINT_IPV4 == hint&HINT_IPV6 {
				address = append(GetIP(name, 1, hint, u, records), GetIP(name, 28, hint, u, records)...)
			} else if hint&HINT_IPV4 != 0 {
				address = GetIP(name, 1, hint, u, records)
			} else if hint&HINT_IPV6 != 0 {
				address = GetIP(name, 28, hint, u, records)
			}
		}
	}

	return records.Index, address
}

func NSRequest(request []byte, cache bool) (uint32, []byte) {
	name, qtype, end := GetQName(request)
	binary.BigEndian.PutUint16(request[10:12], 0)
	request = request[:end]
	if name == "" {
		logPrintln(2, "DNS Segmentation fault")
		return 0, nil
	}

	var records *DNSRecords
	if cache {
		records = LoadDNSCache(name)
		if records == nil {
			records = new(DNSRecords)
			StoreDNSCache(name, records)

			offset := 0
			for i := 0; i < SubdomainDepth; i++ {
				off := strings.Index(name[offset:], ".")
				if off == -1 {
					break
				}
				offset += off
				top := LoadDNSCache(name[offset:])
				if top != nil {
					*records = *top
					break
				}
				offset++
			}
		}
	} else {
		records = new(DNSRecords)
	}

	CurrentTime := time.Now().Unix()
	IsUnknownType := false

	switch qtype {
	case 1:
		if records.IPv4Hint != nil {
			if records.IPv4Hint.TTL == 0 || records.IPv4Hint.TTL > CurrentTime {
				return records.Index, records.BuildResponse(request, qtype, 60)
			}
			records.IPv4Hint = nil
		}
	case 28:
		if records.IPv6Hint != nil {
			if records.IPv6Hint.TTL == 0 || records.IPv6Hint.TTL > CurrentTime {
				return records.Index, records.BuildResponse(request, qtype, 60)
			}
			records.IPv6Hint = nil
		}
	case 65:
		if records.ALPN&(HINT_ALPN|HINT_HTTP|HINT_HTTPS|HINT_HTTP3) != 0 {
			return records.Index, records.BuildResponse(request, qtype, 3600)
		}
	default:
		IsUnknownType = true
	}

	var response []byte
	var err error

	pface := DefaultProfile.GetInterface(name)
	var options ServerOptions
	DNS := ""
	if pface != nil {
		records.ALPN = pface.Hint & HINT_DNS
		logPrintln(2, "request:", name, pface.DNS, pface.Protocol)
		DNS = pface.DNS
	} else {
		logPrintln(4, "request:", name, "no answer")
		return 0, records.BuildResponse(request, qtype, 3600)
	}

	UseVaddr := (pface.Hint&HINT_MODIFY) != 0 || pface.Protocol != 0
	if UseVaddr {
		if DNS == "" {
			if records.Index == 0 {
				NoseLock.Lock()
				records.Index = uint32(len(Nose))
				Nose = append(Nose, name)
				NoseLock.Unlock()
			}
			return records.Index, records.BuildResponse(request, qtype, 3600)
		} else if IsUnknownType {
			return records.Index, records.BuildResponse(request, qtype, 3600)
		}
	}

	u, err := url.Parse(DNS)
	if err != nil {
		logPrintln(1, err)
		return 0, nil
	}

	_request := request
	_qtype := uint16(qtype)
	if u.RawQuery != "" {
		if records.ALPN&HINT_IPV6 != 0 {
			_qtype = 28
		}

		options = ParseOptions(u.RawQuery)

		if options.Type == "A" && qtype == 28 {
			return records.Index, records.BuildResponse(request, qtype, 0)
		} else if options.Type == "AAAA" && qtype == 1 {
			return records.Index, records.BuildResponse(request, qtype, 0)
		}

		if options.ECS != "" || _qtype != uint16(qtype) {
			id := binary.BigEndian.Uint16(request[:2])
			_request = PackRequest(name, _qtype, id, options.ECS)
		}
	}

	switch u.Scheme {
	case "udp":
		response, err = UDPlookup(_request, u.Host)
	case "tcp":
		response, err = TCPlookup(_request, u.Host, nil)
	case "tls":
		response, err = TLSlookup(_request, u.Host)
	case "https":
		response, err = HTTPSlookup(_request, u, options.Domain)
	case "tfo":
		response, err = TFOlookup(_request, u.Host)
	default:
		logPrintln(1, "unknown protocol", u.Scheme)
		return 0, nil
	}

	if err != nil {
		logPrintln(1, err)
		return 0, nil
	}

	switch _qtype {
	case 1:
		records.GetAnswers(response, options)
		if records.IPv4Hint == nil && options.Fallback != nil {
			if options.Fallback.To4() != nil {
				logPrintln(4, "request:", name, "fallback", options.Fallback)
				records.IPv4Hint = &RecordAddresses{0, []net.IP{options.Fallback}}
			}
		}
		if records.IPv4Hint == nil {
			logPrintln(4, "request:", name, qtype, "no answer")
			records.IPv4Hint = &RecordAddresses{0, []net.IP{}}
			return 0, records.BuildResponse(request, qtype, 0)
		}
		logPrintln(3, "response:", name, qtype, records.IPv4Hint.Addresses)
	case 28:
		records.GetAnswers(response, options)
		if records.IPv6Hint == nil && options.Fallback != nil {
			if options.Fallback.To4() == nil {
				logPrintln(4, "request:", name, "fallback", options.Fallback)
				records.IPv6Hint = &RecordAddresses{0, []net.IP{options.Fallback}}
			}
		}
		if records.IPv6Hint == nil {
			logPrintln(4, "request:", name, qtype, "no answer")
			records.IPv6Hint = &RecordAddresses{0, []net.IP{}}
			return 0, records.BuildResponse(request, qtype, 0)
		}
		logPrintln(3, "response:", name, qtype, records.IPv6Hint.Addresses)
	default:
		return 0, response
	}

	if UseVaddr && (records.Index == 0) {
		NoseLock.Lock()
		records.Index = uint32(len(Nose))
		Nose = append(Nose, name)
		NoseLock.Unlock()
	}

	return records.Index, records.BuildResponse(request, qtype, 0)
}

func (server *PhantomInterface) ResolveTCPAddr(host string, port int) (*net.TCPAddr, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}

	_, addrs := NSLookup(host, server.Hint, server.DNS)
	if len(addrs) == 0 {
		return nil, errors.New("no such host")
	}
	rand.Seed(time.Now().UnixNano())
	return &net.TCPAddr{IP: addrs[rand.Intn(len(addrs))], Port: port}, nil
}

func (server *PhantomInterface) ResolveTCPAddrs(host string, port int) ([]*net.TCPAddr, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		tcpAddrs := make([]*net.TCPAddr, 1)
		tcpAddrs[0] = &net.TCPAddr{IP: ip, Port: port}
		return tcpAddrs, nil
	}

	_, addrs := NSLookup(host, server.Hint, server.DNS)
	if len(addrs) == 0 {
		return nil, errors.New("no such host")
	}
	tcpAddrs := make([]*net.TCPAddr, len(addrs))
	for i, addr := range addrs {
		tcpAddrs[i] = &net.TCPAddr{IP: addr, Port: port}
	}

	return tcpAddrs, nil
}

func DNSTCPServer(client net.Conn) {
	defer client.Close()

	var data [2048]byte
	n, err := client.Read(data[:])
	if err != nil {
		return
	}
	requestLen := int(binary.BigEndian.Uint16(data[:2]))
	if requestLen > (n - 2) {
		return
	}
	request := make([]byte, requestLen)
	copy(request, data[2:requestLen+2])

	_, response := NSRequest(request, true)
	responseLen := len(response)
	binary.BigEndian.PutUint16(data[:2], uint16(responseLen))
	copy(data[2:], response)
	client.Write(data[:responseLen+2])
}

func DoHServer(w http.ResponseWriter, req *http.Request) {
	var data [2048]byte
	n, err := req.Body.Read(data[:])
	if err != nil {
		return
	}
	request := data[:n]
	_, response := NSRequest(request, true)

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(response)
}
