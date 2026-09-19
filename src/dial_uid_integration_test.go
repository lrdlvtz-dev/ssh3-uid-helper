//go:build linux

package cmd

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func assertSocketUID(t *testing.T, connection syscall.Conn, expected uint32) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var state unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) {
		statErr = unix.Fstat(int(fd), &state)
	}); err != nil {
		t.Fatal(err)
	}
	if statErr != nil || state.Uid != expected {
		t.Fatalf("socket uid=%d, want %d (error=%v)", state.Uid, expected, statErr)
	}
}

func TestRealDaemonTCPAndUDP(t *testing.T) {
	if os.Getenv("CMXSAFE_HELPER_INTEGRATION") != "1" {
		t.Skip("set CMXSAFE_HELPER_INTEGRATION=1 inside the disposable test container")
	}
	uid64, err := strconv.ParseUint(os.Getenv("CMXSAFE_HELPER_TEST_UID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	helperSocketPath = os.Getenv("CMXSAFE_HELPER_TEST_SOCKET")
	helperExpectedUID = 0
	serviceUID64, err := strconv.ParseUint(os.Getenv("CMXSAFE_HELPER_TEST_SERVICE_UID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	serviceUID := uint32(serviceUID64)

	tcpListener, err := listenIdentityTCP(serviceUID, 19443)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	assertSocketUID(t, tcpListener, serviceUID)
	tcpServiceDone := make(chan error, 1)
	go func() {
		connection, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			tcpServiceDone <- acceptErr
			return
		}
		defer connection.Close()
		buffer := make([]byte, 32)
		length, readErr := connection.Read(buffer)
		if readErr == nil {
			_, readErr = connection.Write(buffer[:length])
		}
		tcpServiceDone <- readErr
	}()

	udpService, err := bindIdentityUDP(serviceUID, 16353)
	if err != nil {
		t.Fatal(err)
	}
	defer udpService.Close()
	assertSocketUID(t, udpService, serviceUID)
	udpServiceDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		length, peer, readErr := udpService.ReadFromUDP(buffer)
		if readErr == nil {
			_, readErr = udpService.WriteToUDP(buffer[:length], peer)
		}
		udpServiceDone <- readErr
	}()

	tcp, err := dialIdentityTCP(uint32(uid64), &net.TCPAddr{IP: net.ParseIP("fd00::20"), Port: 18443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Write([]byte("go-tcp")); err != nil {
		t.Fatal(err)
	}
	tcpReply := make([]byte, 6)
	if _, err := tcp.Read(tcpReply); err != nil || string(tcpReply) != "go-tcp" {
		t.Fatalf("TCP echo: %q, %v", tcpReply, err)
	}
	tcp.Close()

	udp, err := dialIdentityUDP(uint32(uid64), &net.UDPAddr{IP: net.ParseIP("fd00::20"), Port: 15353})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write([]byte("go-udp")); err != nil {
		t.Fatal(err)
	}
	udpReply := make([]byte, 6)
	if _, err := udp.Read(udpReply); err != nil || string(udpReply) != "go-udp" {
		t.Fatalf("UDP echo: %q, %v", udpReply, err)
	}
	udp.Close()

	serviceTCP, err := dialIdentityTCP(uint32(uid64), &net.TCPAddr{IP: net.ParseIP("fd00::20"), Port: 19443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serviceTCP.Write([]byte("helper-listen-tcp")); err != nil {
		t.Fatal(err)
	}
	serviceTCPReply := make([]byte, len("helper-listen-tcp"))
	if _, err := serviceTCP.Read(serviceTCPReply); err != nil || string(serviceTCPReply) != "helper-listen-tcp" {
		t.Fatalf("helper TCP listener echo: %q, %v", serviceTCPReply, err)
	}
	serviceTCP.Close()

	serviceUDP, err := dialIdentityUDP(uint32(uid64), &net.UDPAddr{IP: net.ParseIP("fd00::20"), Port: 16353})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serviceUDP.Write([]byte("helper-bind-udp")); err != nil {
		t.Fatal(err)
	}
	serviceUDP.SetReadDeadline(time.Now().Add(time.Second))
	serviceUDPReply := make([]byte, len("helper-bind-udp"))
	if _, err := serviceUDP.Read(serviceUDPReply); err != nil || string(serviceUDPReply) != "helper-bind-udp" {
		t.Fatalf("helper UDP service echo: %q, %v", serviceUDPReply, err)
	}
	serviceUDP.Close()

	if err := <-tcpServiceDone; err != nil {
		t.Fatal(err)
	}
	if err := <-udpServiceDone; err != nil {
		t.Fatal(err)
	}
}
