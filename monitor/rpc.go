package monitor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	log "github.com/sirupsen/logrus"
)

// RPCServer exposes a simple line-delimited JSON interface to the monitor.
// Clients send a TimedEvent as JSON and receive a JSON response indicating
// whether the event was accepted by the monitor.
type RPCServer struct {
	listener net.Listener
	monitor  *Monitor
}

type rpcResponse struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

// StartRPCServer starts a TCP server on the given address and serves requests.
// Each request must be a single-line JSON encoded TimedEvent.
func (m *Monitor) StartRPCServer(addr string) (*RPCServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to start RPC server on %s: %w", addr, err)
	}

	srv := &RPCServer{
		listener: ln,
		monitor:  m,
	}

	go srv.serve()

	return srv, nil
}

// Close stops the RPC server.
func (s *RPCServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}

	return s.listener.Close()
}

func (s *RPCServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Errorf("rpc: accept error: %v", err)
			continue
		}

		go s.handleConn(conn)
	}
}

func (s *RPCServer) handleConn(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()

		var evt TimedEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			s.writeResponse(conn, rpcResponse{
				Allowed: false,
				Error:   fmt.Sprintf("invalid request: %v", err),
			})
			continue
		}
		log.Errorf("RPCServer: received event: %s", evt.Event)
		_, err := s.monitor.ProcessEvent(evt.Event)
		if err != nil {
			s.writeResponse(conn, rpcResponse{
				Allowed: false,
				Error:   err.Error(),
			})
			continue
		}

		s.writeResponse(conn, rpcResponse{Allowed: true})
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		log.Warnf("rpc: connection error: %v", err)
	}
}

func (s *RPCServer) writeResponse(conn net.Conn, resp rpcResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("rpc: failed to marshal response: %v", err)
		return
	}

	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		log.Errorf("rpc: failed to write response: %v", err)
	}
}
