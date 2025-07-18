package vsock

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/vsock-listener/k8s"
	"github.com/stackrox/rox/vsock-listener/relay"
	"golang.org/x/sys/unix"
)

var (
	log = logging.LoggerForModule()
)

// Server implements a VSOCK server that listens for VM agent connections
type Server struct {
	ctx       context.Context
	cancel    context.CancelFunc
	port      uint32
	listener  net.Listener
	vmWatcher *k8s.VMWatcher
	relay     *relay.SensorRelay
	stopper   concurrency.Stopper
	wg        sync.WaitGroup
}

// NewServer creates a new VSOCK server
func NewServer(ctx context.Context, port uint32, vmWatcher *k8s.VMWatcher, relay *relay.SensorRelay) (*Server, error) {
	ctx, cancel := context.WithCancel(ctx)
	
	return &Server{
		ctx:       ctx,
		cancel:    cancel,
		port:      port,
		vmWatcher: vmWatcher,
		relay:     relay,
		stopper:   concurrency.NewStopper(),
	}, nil
}

// Start starts the VSOCK server
func (s *Server) Start() error {
	log.Infof("Starting VSOCK server on port %d", s.port)
	
	// Create VSOCK listener
	listener, err := s.createVSockListener()
	if err != nil {
		return errors.Wrap(err, "failed to create VSOCK listener")
	}
	s.listener = listener
	
	// Start accepting connections
	s.wg.Add(1)
	go s.acceptConnections()
	
	log.Infof("VSOCK server started on port %d", s.port)
	return nil
}

// Stop stops the VSOCK server
func (s *Server) Stop() error {
	log.Info("Stopping VSOCK server...")
	
	s.cancel()
	s.stopper.Client().Stop()
	
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.Warnf("Error closing VSOCK listener: %v", err)
		}
	}
	
	s.wg.Wait()
	
	log.Info("VSOCK server stopped")
	return nil
}

// createVSockListener creates a VSOCK listener
func (s *Server) createVSockListener() (net.Listener, error) {
	// Create VSOCK socket
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create VSOCK socket")
	}
	
	// Set socket options
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, errors.Wrap(err, "failed to set SO_REUSEADDR")
	}
	
	// Bind to VSOCK address
	// Host side uses CID 2 (VMADDR_CID_HOST)
	addr := &unix.SockaddrVM{
		CID:  unix.VMADDR_CID_HOST,
		Port: s.port,
	}
	
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, errors.Wrapf(err, "failed to bind to VSOCK address %d:%d", unix.VMADDR_CID_HOST, s.port)
	}
	
	// Listen for connections
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return nil, errors.Wrap(err, "failed to listen on VSOCK socket")
	}
	
	// Convert to net.Listener
	file := os.NewFile(uintptr(fd), "vsock")
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("failed to create file from VSOCK socket")
	}
	
	listener, err := net.FileListener(file)
	if err != nil {
		file.Close()
		return nil, errors.Wrap(err, "failed to create listener from file")
	}
	
	file.Close() // FileListener takes ownership
	return listener, nil
}

// acceptConnections accepts incoming VSOCK connections
func (s *Server) acceptConnections() {
	defer s.wg.Done()
	
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return // Context canceled, expected error
			}
			log.Errorf("Failed to accept VSOCK connection: %v", err)
			continue
		}
		
		// Handle connection in separate goroutine
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single VSOCK connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	
	// Get peer CID from connection
	peerCID, err := s.getPeerCID(conn)
	if err != nil {
		log.Errorf("Failed to get peer CID: %v", err)
		return
	}
	
	// Validate VM
	vmInfo, exists := s.vmWatcher.GetVMByCID(peerCID)
	if !exists {
		log.Warnf("Received connection from unknown VM with CID %d", peerCID)
		return
	}
	
	log.Infof("Accepted connection from VM %s/%s (CID: %d)", vmInfo.Namespace, vmInfo.Name, peerCID)
	
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	
	// Handle the connection
	if err := s.processVMConnection(conn, vmInfo); err != nil {
		log.Errorf("Error processing connection from VM %s/%s: %v", vmInfo.Namespace, vmInfo.Name, err)
	}
}

// getPeerCID extracts the peer CID from a VSOCK connection
func (s *Server) getPeerCID(conn net.Conn) (uint32, error) {
	// For VSOCK connections, we need to extract the CID from the socket
	// This is a simplified implementation - in practice, you'd use syscalls
	// to get the actual peer address
	
	// Parse the remote address string
	// Format is typically "vsock:cid:port" or similar
	remoteAddr := conn.RemoteAddr().String()
	
	// This is a placeholder - actual implementation would need to
	// use syscalls to get the real peer CID
	log.Debugf("Connection from remote address: %s", remoteAddr)
	
	// For now, we'll try to extract from a test connection
	// In a real implementation, you'd use unix.Getsockname() or similar
	return 0, errors.New("CID extraction not implemented - needs syscall implementation")
}

// processVMConnection processes data from a VM connection
func (s *Server) processVMConnection(conn net.Conn, vmInfo *k8s.VMInfo) error {
	// Read message header (4 bytes length + 4 bytes message type)
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return errors.Wrap(err, "failed to read message header")
	}
	
	messageLen := binary.LittleEndian.Uint32(header[:4])
	messageType := binary.LittleEndian.Uint32(header[4:8])
	
	// Validate message length
	if messageLen > 1024*1024 { // 1MB limit
		return errors.Errorf("message too large: %d bytes", messageLen)
	}
	
	// Read message body
	body := make([]byte, messageLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return errors.Wrap(err, "failed to read message body")
	}
	
	log.Debugf("Received message from VM %s/%s: type=%d, len=%d", 
		vmInfo.Namespace, vmInfo.Name, messageType, messageLen)
	
	// Create VM data message
	vmData := &relay.VMData{
		VMUID:       vmInfo.UID,
		VMName:      vmInfo.Name,
		VMNamespace: vmInfo.Namespace,
		MessageType: messageType,
		Data:        body,
		Timestamp:   time.Now(),
	}
	
	// Send to sensor relay
	if err := s.relay.SendVMData(vmData); err != nil {
		return errors.Wrap(err, "failed to send VM data to relay")
	}
	
	// Send acknowledgment
	ack := make([]byte, 4)
	binary.LittleEndian.PutUint32(ack, 0) // 0 = success
	if _, err := conn.Write(ack); err != nil {
		return errors.Wrap(err, "failed to send acknowledgment")
	}
	
	return nil
}