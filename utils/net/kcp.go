// Copyright 2017 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package net

import (
	"crypto/sha256"
	"fmt"
	"net"

	"github.com/fatedier/frp/utils/log"

	kcp "github.com/fatedier/kcp-go"
)

type KcpListener struct {
	net.Addr
	listener  net.Listener
	accept    chan Conn
	closeFlag bool
	log.Logger
}

func ListenKcp(bindAddr string, bindPort int, secret string) (l *KcpListener, err error) {
	var block kcp.BlockCrypt

	// AES256, ignore error
	if secret != "" {
		hash := sha256.Sum256([]byte(secret))
		block, _ = kcp.NewAESBlockCrypt(hash[:])
	}

	listener, err := kcp.ListenWithOptions(fmt.Sprintf("%s:%d", bindAddr, bindPort), block, 10, 3)
	if err != nil {
		return l, err
	}
	listener.SetReadBuffer(4194304)
	listener.SetWriteBuffer(4194304)

	l = &KcpListener{
		Addr:      listener.Addr(),
		listener:  listener,
		accept:    make(chan Conn),
		closeFlag: false,
		Logger:    log.NewPrefixLogger(""),
	}

	go func() {
		for {
			conn, err := listener.AcceptKCP()
			if err != nil {
				if l.closeFlag {
					close(l.accept)
					return
				}
				continue
			}
			conn.SetStreamMode(true)
			conn.SetWriteDelay(true)
			conn.SetNoDelay(1, 20, 2, 1)
			conn.SetMtu(1350)
			conn.SetWindowSize(1024, 1024)
			conn.SetACKNoDelay(false)

			l.accept <- WrapConn(conn)
		}
	}()
	return l, err
}

func (l *KcpListener) Accept() (Conn, error) {
	conn, ok := <-l.accept
	if !ok {
		return conn, fmt.Errorf("channel for kcp listener closed")
	}
	return conn, nil
}

func (l *KcpListener) Close() error {
	if !l.closeFlag {
		l.closeFlag = true
		l.listener.Close()
	}
	return nil
}

func NewKcpConnFromUdp(conn *net.UDPConn, connected bool, raddr string, secret string) (net.Conn, error) {
	var block kcp.BlockCrypt

	// AES256, ignore error
	if secret != "" {
		hash := sha256.Sum256([]byte(secret))
		block, _ = kcp.NewAESBlockCrypt(hash[:])
	}

	kcpConn, err := kcp.NewConnEx(1, connected, raddr, block, 10, 3, conn)
	if err != nil {
		return nil, err
	}
	kcpConn.SetStreamMode(true)
	kcpConn.SetWriteDelay(true)
	kcpConn.SetNoDelay(1, 20, 2, 1)
	kcpConn.SetMtu(1350)
	kcpConn.SetWindowSize(1024, 1024)
	kcpConn.SetACKNoDelay(false)
	return kcpConn, nil
}

func NewKcpConn(raddr, secret string) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, err
	}

	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	return NewKcpConnFromUdp(c, true, raddr, secret)
}
