// Package streamnet adapts a local byte-stream connection to gophertunnel's
// packet-oriented transport contract.
package streamnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

const (
	// MaxFrameLen is the largest local transport frame accepted by the bridge.
	MaxFrameLen = 64 * 1024 * 1024
	maxFrameLen = MaxFrameLen
)

var (
	// ErrInvalidFrameLength is returned for an empty local transport frame.
	ErrInvalidFrameLength = errors.New("streamnet: frame length must be positive")
	// ErrFrameTooLarge is returned when a local transport frame exceeds MaxFrameLen.
	ErrFrameTooLarge = errors.New("streamnet: frame exceeds 64 MiB")
)

// FramedConn wraps a net.Conn with an unsigned 32-bit big-endian length prefix.
// Each Write is one complete frame and ReadPacket reads one complete frame.
type FramedConn struct {
	net.Conn
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
	onClose   func()
}

// NewFramedConn wraps conn in the local bridge framing contract.
func NewFramedConn(conn net.Conn) *FramedConn {
	return &FramedConn{Conn: conn}
}

// DisableEncryption keeps the local Rust bridge on its already-private
// transport without negotiating Bedrock's per-batch AES-CTR wrapper.
func (c *FramedConn) DisableEncryption() bool { return true }

func newTrackedFramedConn(conn net.Conn, onClose func()) *FramedConn {
	return &FramedConn{Conn: conn, onClose: onClose}
}

// Close closes the underlying transport once and unregisters tracked server connections.
func (c *FramedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}

// ReadPacket reads exactly one framed payload. A clean EOF is only returned
// when it occurs between frames.
func (c *FramedConn) ReadPacket() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return nil, fmt.Errorf("streamnet: read frame header: %w", classifyTerminalError(err))
	}
	length := binary.BigEndian.Uint32(header[:])
	if err := validateFrameLength64(uint64(length)); err != nil {
		return nil, err
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return nil, fmt.Errorf("streamnet: read frame payload: %w", classifyTerminalError(err))
	}
	return payload, nil
}

// Write writes b as one complete framed payload. Concurrent calls remain
// frame-atomic and preserve mutex acquisition order.
func (c *FramedConn) Write(b []byte) (int, error) {
	if err := validateFrameLength(len(b)); err != nil {
		return 0, err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	written64, err := (net.Buffers{header[:], b}).WriteTo(c.Conn)
	written := int(written64)
	if written < len(header) {
		if err == nil {
			err = io.ErrNoProgress
		}
		return 0, fmt.Errorf("streamnet: write frame header: %w", classifyTerminalError(err))
	}
	payloadWritten := written - len(header)
	if err != nil || payloadWritten != len(b) {
		if err == nil {
			err = io.ErrNoProgress
		}
		return payloadWritten, fmt.Errorf("streamnet: write frame payload: %w", classifyTerminalError(err))
	}
	return len(b), nil
}

func classifyTerminalError(err error) error {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return err
	}
	if isEntirelyTerminal(err) {
		return &terminalError{cause: err}
	}
	return err
}

func isEntirelyTerminal(err error) bool {
	if err == nil {
		return false
	}
	if terminal, ok := err.(interface{ TerminalClose() bool }); ok && terminal.TerminalClose() {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !isEntirelyTerminal(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil {
			return isEntirelyTerminal(child)
		}
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, os.ErrClosed) ||
		isPlatformTerminalError(err)
}

type terminalError struct {
	cause error
}

func (err *terminalError) Error() string { return err.cause.Error() }
func (err *terminalError) Unwrap() error { return err.cause }
func (err *terminalError) Is(target error) bool {
	return target == net.ErrClosed || errors.Is(err.cause, target)
}

// TerminalClose reports that this error is a positively identified terminal local transport failure.
// The exported marker method allows other packages to classify the wrapper without depending on its type.
func (err *terminalError) TerminalClose() bool { return true }

func validateFrameLength(length int) error {
	if length < 0 {
		return ErrInvalidFrameLength
	}
	return validateFrameLength64(uint64(length))
}

func validateFrameLength64(length uint64) error {
	if length == 0 {
		return ErrInvalidFrameLength
	}
	if length > MaxFrameLen {
		return fmt.Errorf("%w: got %d bytes, maximum is %d", ErrFrameTooLarge, length, MaxFrameLen)
	}
	return nil
}

