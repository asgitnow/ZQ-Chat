// echbridge —— 本地明文 WebSocket ↔ 远端 wss://(ECH) 桥
//
// 背景：workers.dev 预览域名在部分网络环境被 DNS 污染 + TLS SNI 阻断。
// 本桥用 Go 原生 crypto/tls 的客户端 ECH（RFC 9849）把真实 SNI 藏进加密的
// ClientHelloInner，外层只见 Cloudflare 公共 ECH 前端名 cloudflare-ech.com。
// headless 客户端把 wss://host 换成 ws://127.0.0.1:<port> 即可与真实部署通信。
//
// 用法:
//   echbridge [-listen 127.0.0.1:18443] [-host H] [-ip IP] [-ech-b64 CFG]
//
// ECHConfig 默认内嵌 Cloudflare 公共 ECH 配置（来自 cloudflare-ech.com 的
// HTTPS(Type65) 记录，2026-10 采样；CF 密钥轮换后需刷新）。
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const defaultECHConfigB64 = "AEX+DQBBwgAgACAfkzL2pc7gCXT2EyF0E2vlbWYDYeqwiJAt293mlzb3agAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

var (
	targetHost = flag.String("host", "chat.honeysuckle-hydrant.workers.dev", "远端真实主机名（inner SNI）")
	targetIP   = flag.String("ip", "104.18.10.118", "连接用 IP（Cloudflare anycast）")
	echB64     = flag.String("ech-b64", defaultECHConfigB64, "ECHConfigList base64")
	listen     = flag.String("listen", "127.0.0.1:18443", "本地 ws:// 监听地址")
)

func main() {
	flag.Parse()
	echList, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*echB64))
	if err != nil {
		log.Fatalf("ech-b64 解码失败: %v", err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("echbridge listening on ws://%s -> wss://%s (ECH via %s)", *listen, *targetHost, *targetIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleLocal(c, echList)
	}
}

func handleLocal(c net.Conn, echList []byte) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("local http: %v", err)
		return
	}
	key := req.Header.Get("Sec-WebSocket-Key")

	remote, err := dialECH(echList)
	if err != nil {
		log.Printf("dial: %v", err)
		return
	}
	defer remote.Close()

	if key == "" {
		// 非 WS（如 curl）：原始透传，便于调试远端 HTTP 响应
		// ★ Host 必须重写为远端主机名，否则 CF 边缘路由不到 zone（403）
		req.Host = *targetHost
		req.Write(remote)
		if br.Buffered() > 0 {
			buf, _ := br.Peek(br.Buffered())
			remote.Write(buf)
		}
		go io.Copy(remote, c)
		io.Copy(c, remote)
		return
	}

	// 本地侧回 101
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n\r\n"
	if _, err := c.Write([]byte(resp)); err != nil {
		return
	}

	// 远端侧 WS 握手（path 原样透传）
	rbr, err := remoteWSHandshake(remote, req.URL.RequestURI())
	if err != nil {
		log.Printf("remote ws: %v", err)
		return
	}
	log.Printf("bridge up: %s <-> wss://%s%s", req.URL.Path, *targetHost, req.URL.RequestURI())

	closed := make(chan struct{})
	go func() {
		forwardClientToServer(c, remote)
		select {
		case <-closed:
		default:
			remote.Write([]byte{0x88, 0x02, 0x03, 0xE8}) // close 1000
		}
		close(closed)
	}()
	forwardServerToClient(rbr, c)
	select {
	case <-closed:
	default:
		close(closed)
	}
}

func dialECH(echList []byte) (net.Conn, error) {
	cfg := &tls.Config{
		ServerName:                     *targetHost, // inner SNI = 真实主机
		EncryptedClientHelloConfigList: echList,
		MinVersion:                     tls.VersionTLS13, // ECH 要求 TLS1.3；失败不降级
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", *targetIP+":443", cfg)
	if err != nil {
		return nil, err
	}
	st := conn.ConnectionState()
	if !st.ECHAccepted {
		return nil, fmt.Errorf("ECH 未被服务器接受")
	}
	log.Printf("TLS ok: ECHAccepted=true")
	return conn, nil
}

func remoteWSHandshake(conn net.Conn, path string) (*bufio.Reader, error) {
	kb := make([]byte, 16)
	if _, err := rand.Read(kb); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(kb)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, *targetHost, key)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 101 {
		return nil, fmt.Errorf("remote ws status %d", resp.StatusCode)
	}
	return br, nil
}

func wsAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// forwardClientToServer: 读取本地客户端的掩码帧，去掩码后以未掩码帧转发给远端
func forwardClientToServer(local, remote net.Conn) {
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(local, hdr); err != nil {
			return
		}
		b0 := hdr[0]
		masked := hdr[1]&0x80 != 0
		ln := int(hdr[1] & 0x7F)
		switch {
		case ln == 126:
			e := make([]byte, 2)
			if _, err := io.ReadFull(local, e); err != nil {
				return
			}
			ln = int(e[0])<<8 | int(e[1])
		case ln == 127:
			e := make([]byte, 8)
			if _, err := io.ReadFull(local, e); err != nil {
				return
			}
			ln = 0
			for i := 0; i < 8; i++ {
				ln = ln<<8 | int(e[i])
			}
		}
		if ln > 16*1024*1024 {
			return
		}
		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			if _, err := io.ReadFull(local, maskKey); err != nil {
				return
			}
		}
		buf := make([]byte, ln)
		if _, err := io.ReadFull(local, buf); err != nil {
			return
		}
		if masked {
			for i := range buf {
				buf[i] ^= maskKey[i%4]
			}
		}
		var out []byte
		if ln < 126 {
			out = append(out, b0, byte(ln))
		} else if ln < 65536 {
			out = append(out, b0, 126, byte(ln>>8), byte(ln))
		} else {
			out = append(out, b0, 127)
			for i := 7; i >= 0; i-- {
				out = append(out, byte(ln>>(8*i)))
			}
		}
		out = append(out, buf...)
		if _, err := remote.Write(out); err != nil {
			return
		}
		if b0&0x0F == 8 {
			return
		}
	}
}

// forwardServerToClient: 远端未掩码帧原样写回本地客户端
func forwardServerToClient(r io.Reader, local io.Writer) {
	buf := make([]byte, 64*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := local.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
