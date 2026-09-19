//go:build linux

package cmd

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReceiveHelperReplyWaitsForDelayedDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		time.Sleep(100 * time.Millisecond)
		reply := make([]byte, helperReplySize)
		binary.BigEndian.PutUint32(reply[0:4], helperMagic)
		binary.BigEndian.PutUint16(reply[4:6], helperVersion)
		_, writeErr := connection.Write(reply)
		done <- writeErr
	}()
	client, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	payload, _, err := receiveHelperReply(client)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 75*time.Millisecond || len(payload) != helperReplySize {
		t.Fatalf("delayed reply was not awaited correctly")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestValidateHelperPeerRejectsUnexpectedUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		connection, _ := listener.AcceptUnix()
		accepted <- connection
	}()
	client, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	previous := helperExpectedUID
	helperExpectedUID = uint32(os.Getuid() + 1)
	defer func() { helperExpectedUID = previous }()
	if err := validateHelperPeer(client); err == nil {
		t.Fatal("unexpected daemon uid was trusted")
	}
}

func TestValidateIdentityConnectionRejectsWrongDestination(t *testing.T) {
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		connection, _ := listener.AcceptTCP()
		accepted <- connection
	}()
	connection, err := net.DialTCP("tcp6", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	server := <-accepted
	defer server.Close()
	local := connection.LocalAddr().(*net.TCPAddr)
	wrong := &net.UDPAddr{IP: net.ParseIP("::1"), Port: listener.Addr().(*net.TCPAddr).Port + 1}
	if err := verifyIdentityConnection(connection, local.IP, wrong, unix.SOCK_STREAM); err == nil {
		t.Fatal("descriptor connected to the wrong destination was accepted")
	}
}

func TestBuildHelperRequestTCP(t *testing.T) {
	destination := &net.UDPAddr{IP: net.ParseIP("fd00::20"), Port: 443}
	request, requestID, socketType, err := buildHelperRequest(1007, "tcp6", destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != helperRequestSize || requestID == 0 || socketType != unix.SOCK_STREAM {
		t.Fatalf("unexpected request metadata: len=%d id=%d type=%d", len(request), requestID, socketType)
	}
	if got := binary.BigEndian.Uint32(request[0:4]); got != helperMagic {
		t.Fatalf("magic=%x", got)
	}
	if got := binary.BigEndian.Uint16(request[6:8]); got != helperOpTCP {
		t.Fatalf("operation=%d", got)
	}
	if got := binary.BigEndian.Uint32(request[16:20]); got != 1007 {
		t.Fatalf("uid=%d", got)
	}
	if got := binary.BigEndian.Uint16(request[20:22]); got != 443 {
		t.Fatalf("port=%d", got)
	}
	if got := net.IP(request[24:40]); !got.Equal(destination.IP) {
		t.Fatalf("destination=%s", got)
	}
}

func TestBuildHelperRequestUDP(t *testing.T) {
	request, _, socketType, err := buildHelperRequest(42, "udp6", &net.UDPAddr{
		IP: net.ParseIP("2001:db8::53"), Port: 53,
	})
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(request[6:8]) != helperOpUDP || socketType != unix.SOCK_DGRAM {
		t.Fatalf("UDP request was not encoded as datagram")
	}
}

func TestBuildHelperServiceRequests(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		operation uint16
		sockType  int
	}{
		{"tcp-listener", "tcp6", helperOpListenTCP, unix.SOCK_STREAM},
		{"udp-service", "udp6", helperOpBindUDP, unix.SOCK_DGRAM},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, requestID, socketType, err := buildHelperServiceRequest(1007, test.network, 9443)
			if err != nil {
				t.Fatal(err)
			}
			if requestID == 0 || socketType != test.sockType {
				t.Fatalf("unexpected request metadata: id=%d type=%d", requestID, socketType)
			}
			if got := binary.BigEndian.Uint16(request[6:8]); got != test.operation {
				t.Fatalf("operation=%d", got)
			}
			if got := binary.BigEndian.Uint16(request[20:22]); got != 9443 {
				t.Fatalf("port=%d", got)
			}
			if got := net.IP(request[24:40]); !got.IsUnspecified() {
				t.Fatalf("service request supplied bind address %s", got)
			}
		})
	}
}

func TestBuildHelperServiceRequestRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		network string
		port    int
	}{
		{"tcp6", 0},
		{"tcp6", 443},
		{"udp6", 65536},
		{"tcp", 443},
	} {
		if _, _, _, err := buildHelperServiceRequest(1, test.network, test.port); err == nil {
			t.Fatalf("accepted service request network=%q port=%d", test.network, test.port)
		}
	}
}

func TestBuildHelperAcceptRequest(t *testing.T) {
	request, requestID, err := buildHelperAcceptRequest(1007, 9443)
	if err != nil {
		t.Fatal(err)
	}
	if requestID == 0 || binary.BigEndian.Uint16(request[6:8]) != helperOpAcceptTCP ||
		binary.BigEndian.Uint16(request[20:22]) != 9443 || !net.IP(request[24:40]).IsUnspecified() {
		t.Fatal("invalid TCP accept request")
	}
}

func TestBuildHelperRequestRejectsInvalidDestinations(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		destination *net.UDPAddr
	}{
		{"nil", "tcp6", nil},
		{"ipv4", "tcp6", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}},
		{"loopback", "tcp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 80}},
		{"multicast", "udp6", &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 53}},
		{"zero-port", "tcp6", &net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: 0}},
		{"zone", "udp6", &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 53, Zone: "eth0"}},
		{"network", "tcp", &net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: 80}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, err := buildHelperRequest(1, test.network, test.destination); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func FuzzBuildHelperRequest(f *testing.F) {
	f.Add([]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, uint16(443), "tcp6")
	f.Add([]byte{0x7f, 0, 0, 1}, uint16(53), "udp6")
	f.Fuzz(func(t *testing.T, rawIP []byte, port uint16, network string) {
		_, _, _, _ = buildHelperRequest(1000, network, &net.UDPAddr{IP: net.IP(rawIP), Port: int(port)})
	})
}

func TestCanonicalIdentityRejectsOrdinaryAccount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test expects the current account not to be a CMXsafe identity")
	}
	if _, err := canonicalIPv6ForUID(0); err == nil {
		t.Fatal("root account accepted as a canonical CMXsafe identity")
	}
}

func TestParseReceivedFDRequiresExactlyOneDescriptor(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	left, right := pair[0], pair[1]
	defer unix.Close(left)
	defer unix.Close(right)
	one, err := parseReceivedFD(unix.UnixRights(left))
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(one)
	if _, err := parseReceivedFD(nil); err == nil {
		t.Fatal("empty ancillary data accepted")
	}
	if _, err := parseReceivedFD(unix.UnixRights(left, right)); err == nil {
		t.Fatal("multiple descriptors accepted")
	}
}
