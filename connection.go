package smb2

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"time"
)

type User struct {
}

const (
	stateCreated = iota
	stateConnectionNegotiated
	stateSessionNegotiateSent
	stateSessionNegotiatted
	stateError
)

const (
	maxTransactSize = 0x800000
)

func mustReadRand(dst []byte) {
	_, err := cryptorand.Read(dst[:])
	if err != nil {
		panic(err)
	}
}

var gServerGuid GUID = func() GUID {
	var g GUID
	mustReadRand(g[:])
	return g
}()

var gSPNEGOResponse = []byte{0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65}

var gTargetName = "t\x00e\x00s\x00t\x00"

type Connection struct {
	lastMessageId int64
	lastProcId    uint32

	state int

	remoteAddr net.Addr

	clientCapabilities uint32
	clientSecurityMode uint16

	clientGuid GUID

	dialect uint16
	salt    [32]byte

	aes128ccm bool
	aes128gcm bool

	usePreauthIntergrityCheck bool

	fp       net.Conn
	writeBuf bytes.Buffer

	serverChallenge [8]byte

	preauth_sessions map[uint64]*Session // TODO: clean up each second
	sessions         map[uint64]*Session

	openUserCallback func(user *User) ([]Tree, error)
}

var gPreauthIntegrityCapabilities = []byte{1, 0, 32, 0, 1, 0}

func (conn *Connection) handleNegotiate(msg []byte) {
	fmt.Printf("DEBUG: %s Negotiate request\n", conn.remoteAddr)

	if conn.state != stateCreated {
		panic(fmt.Errorf("Negotiate request in state %d", conn.state))
	}

	hdr := msg[:SMB2_HEADER_SIZE]
	flags := binary.LittleEndian.Uint32(hdr[16:])

	if flags != 0 {
		fmt.Printf("ERROR: %s Negotiate with flags %x", conn.remoteAddr, flags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	proc_id := binary.LittleEndian.Uint32(hdr[32:])

	if proc_id == 0xfeff {
		fmt.Printf("DEBUG: %s looks like windows client", conn.remoteAddr)
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize > len(req) {
		panic(fmt.Errorf("Negotiate request is too short %d, expected %d", len(req), structureSize))
	}

	conn.clientCapabilities = binary.LittleEndian.Uint32(req[8:])
	conn.clientSecurityMode = binary.LittleEndian.Uint16(req[4:]) // TODO: only 3.x

	copy(conn.clientGuid[:], req[12:])

	dialectCount := int(binary.LittleEndian.Uint16(req[2:]))

	for i := 0; i < dialectCount; i++ {
		dialect := uint16(req[36+i*2+1])<<8 + uint16(req[36+i*2])

		if dialect < 0x0311 && dialect > conn.dialect {
			conn.dialect = dialect
		}
	}

	if conn.dialect != 0x0300 && conn.dialect != 0x0302 && conn.dialect != 0x311 {
		panic(fmt.Errorf("Unsupported dialect %x", conn.dialect))
	}

	fmt.Printf("DEBUG: %s Negatiated dialect %x\n", conn.remoteAddr, conn.dialect)

	if conn.dialect == 0x311 {
		negotiateContextOffset := binary.LittleEndian.Uint32(req[28:]) - SMB2_HEADER_SIZE
		negotiateContextCount := int(binary.LittleEndian.Uint16(req[32:]))

		if negotiateContextCount != 2 {
			panic(fmt.Errorf("negotiateContextCount(%d) != 2", negotiateContextCount))
		}

		for i := 0; i < negotiateContextCount; i++ {
			negctx := req[negotiateContextOffset:]

			negctxType := binary.LittleEndian.Uint16(negctx)
			dataLen := binary.LittleEndian.Uint16(negctx[2:])

			if negctxType == 0x01 {
				preauth := negctx[8 : 8+dataLen]
				if !bytes.Equal(preauth[:len(gPreauthIntegrityCapabilities)], gPreauthIntegrityCapabilities) {
					panic(fmt.Errorf("Unsupported SMB2_PREAUTH_INTEGRITY_CAPABILITIES %v", preauth))
				}
				copy(conn.salt[:], preauth[6:38])
				conn.usePreauthIntergrityCheck = true
			} else if negctxType == 0x02 {
				enccap := negctx[8 : 8+dataLen]
				count := int(enccap[0])
				for i := 0; i < count; i++ {
					cipher := binary.LittleEndian.Uint16(enccap[2+i*2:])
					if cipher == 1 {
						conn.aes128ccm = true
					} else if cipher == 2 {
						conn.aes128gcm = true
					} else {
						fmt.Printf("DEBUG: %s unknown chiper %x", cipher)
					}
				}

			} else {
				panic(fmt.Errorf("Unsupported negotiate context type %d", negctxType))
			}

			dataLen += 8 // add context header size

			if dataLen&7 != 0 {
				negotiateContextOffset += uint32(dataLen&0xFFF8 + 8)
			} else {
				negotiateContextOffset += uint32(dataLen)
			}
		}
	}

	var resp SMB2_NEGOTIATE_Response_Header
	resp.Header.CreditResponse = 1
	resp.StructureSize = 65                            // The server MUST set this field to 65 by [MS-SMB2].pdf
	resp.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED // |SMB2_NEGOTIATE_SIGNING_REQUIRED
	resp.DialectRevision = conn.dialect
	resp.ServerGuid = gServerGuid
	resp.Capabilities = SMB2_GLOBAL_CAP_LARGE_MTU // TODO: check 3.3.5.4, page 259

	if conn.aes128ccm || conn.aes128gcm {
		resp.Capabilities |= SMB2_GLOBAL_CAP_ENCRYPTION
	}

	resp.MaxTransactSize = maxTransactSize
	resp.MaxReadSize = maxTransactSize
	resp.MaxWriteSize = maxTransactSize
	resp.SystemTime = timeToFiletime(time.Now())
	resp.SecurityBufferOffset = 0x80
	resp.SecurityBufferLength = uint16(len(gSPNEGOResponse))

	if conn.dialect == 0x311 {
		resp.NegotiateContextOffset = 0xd0 // SecurityBufferOffset + SecurityBufferLength + padding
	}

	err := conn.writeResponse(func(w *bytes.Buffer) {

		binary.Write(w, binary.LittleEndian, &resp)
		w.Write(gSPNEGOResponse)

		// TODO: add negatiation context
		//if conn.dialect == 0x311 {
		//}
	})

	if err != nil {
		panic(err)
	}

	conn.state = stateConnectionNegotiated
}

func (conn *Connection) handleSessionSetup(msg []byte) {
	fmt.Printf("DEBUG: %s SessionSetup request\n", conn.remoteAddr)

	hdr := msg[:SMB2_HEADER_SIZE]

	flags := binary.LittleEndian.Uint32(hdr[16:])

	if flags&^SMB2_FLAGS_PRIORITY_MASK != 0 {
		panic(fmt.Errorf("SessionSetup with flags %x", flags))
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize > len(req) {
		panic(fmt.Errorf("SessionSetup request is too short %d, expected %d", len(req), structureSize))
	}

	if req[2] != 0 {
		fmt.Printf("ERROR: %s Session binding is not supported", conn.remoteAddr)
		conn.writeErrorResponse(STATUS_NOT_IMPLEMENTED, msg)
		return
	}

	// TODO: check securityMode req[3]

	securityBufferOffset := binary.LittleEndian.Uint16(req[12:])
	securityBufferLength := binary.LittleEndian.Uint16(req[14:])

	previousSessionId := binary.LittleEndian.Uint64(req[16:])
	if previousSessionId != 0 {
		fmt.Printf("ERROR: %s PreviousSessionId is not zero = 0x%x\n", conn.remoteAddr, previousSessionId)
		conn.writeErrorResponse(STATUS_NOT_IMPLEMENTED, msg)
		return
	}

	secblob := msg[securityBufferOffset : securityBufferOffset+securityBufferLength]

	if conn.state != stateConnectionNegotiated {
		panic(fmt.Errorf("conn.state == %d", conn.state))
	}

	// direct NTLMSSP_NEGOTIATE
	if bytes.Equal(secblob[:12], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 1, 0, 0, 0}) {

		neg_flags := binary.LittleEndian.Uint32(secblob[12:]) // see [MS-NLMP].pdf 2.2.2.5

		var mandatoryFlags uint32 = NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_UNICODE

		if neg_flags&mandatoryFlags != mandatoryFlags {
			panic(fmt.Errorf("NTLMSSP with not supported flags %x", neg_flags))
		}

		ns := NewSession()

		if _, ok := conn.sessions[ns.id]; ok {
			panic("internal error")
		}

		conn.preauth_sessions[ns.id] = ns

		var resp SMB2_SESSION_SETUP_Response_Header

		resp.Header.CreditResponse = 1
		resp.Header.Command = SMB2_SESSION_SETUP
		resp.Header.Status = 0xc0000016 // STATUS_MORE_PROCESSING_REQUIRED
		resp.Header.SessionId = ns.id

		resp.StructureSize = 9 // The server MUST set this field to 9 by [MS-SMB2].pdf
		// TODO: resp.SessionFlags set 0x4 if encryption
		resp.SecurityBufferOffset = 0x48

		err := conn.writeResponse(func(w *bytes.Buffer) {

			binary.Write(w, binary.LittleEndian, &resp)

			off := w.Len()

			w.Write([]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 2, 0, 0, 0}) // NTLMSSP_CHALLENGE

			var tmp [4]byte
			if neg_flags&NTLMSSP_REQUEST_TARGET != 0 {

				binary.LittleEndian.PutUint16(tmp[:], uint16(len(gTargetName)))
				binary.LittleEndian.PutUint16(tmp[2:], uint16(len(gTargetName)))
				w.Write(tmp[:])

				binary.LittleEndian.PutUint32(tmp[:], 48) // TargetNameOffset
				w.Write(tmp[:])
			} else {
				w.Write([]byte{0, 0, 0, 0, 48, 0, 0, 0}) // empty TargetName
			}

			// TODO: negotiate sign and always sign for windows
			var resp_flags uint32 = NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_UNICODE | (1 << 17)

			binary.LittleEndian.PutUint32(tmp[:], resp_flags)
			w.Write(tmp[:])

			mustReadRand(conn.serverChallenge[:])
			w.Write(conn.serverChallenge[:])
			w.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})  // reserved
			w.Write([]byte{0, 0, 0, 0, 48, 0, 0, 0}) // TargetInfo
			// Payload
			w.Write([]byte(gTargetName))

			sz := w.Len() - off

			binary.LittleEndian.PutUint16(w.Bytes()[off-2:], uint16(sz))
		})

		if err != nil {
			panic(err)
		}

	} else if bytes.Equal(secblob[:12], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 3, 0, 0, 0}) {
		// direct NTLMSSP_AUTH

		sessionId := binary.LittleEndian.Uint64(msg[40:])

		if s, ok := conn.preauth_sessions[sessionId]; ok {

			trees, err := conn.openUserCallback(nil)

			if err != nil {
				panic(fmt.Errorf("Session open error %v", err))
			}

			var resp SMB2_SESSION_SETUP_Response_Header

			resp.Header.CreditResponse = 1
			resp.Header.Command = SMB2_SESSION_SETUP
			resp.Header.SessionId = sessionId

			resp.StructureSize = 9 // The server MUST set this field to 9 by [MS-SMB2].pdf
			resp.SecurityBufferOffset = 0x48
			resp.SecurityBufferLength = 0
			resp.SessionFlags = 1 // Guest

			err = conn.writeResponse(func(w *bytes.Buffer) {

				binary.Write(w, binary.LittleEndian, &resp)

			})

			delete(conn.preauth_sessions, sessionId)

			if err != nil {
				panic(err)
			}

			conn.sessions[sessionId] = s
			s.addTrees(trees)

		} else {
			panic(fmt.Errorf("Unknown session id %d in SessionSetupRequest2", sessionId))
		}

	} else {
		panic(fmt.Errorf("Unknown SecurityBlob %x", secblob))
	}

}

func (conn *Connection) handleCloseSession(s *Session, msg []byte) {
	fmt.Printf("DEBUG: %s Logoff request\n", conn.remoteAddr)

	s.Close()

	delete(conn.sessions, s.id)

	var resp SMB2_LOGOFF_Response
	resp.Header.CreditResponse = 1
	resp.Header.Command = SMB2_LOGOFF
	resp.Header.SessionId = s.id
	resp.StructureSize = 4
	conn.writeSimpleResponse(resp)
}

func (conn *Connection) handleSMB2Message(msg []byte) {

	protoId := binary.LittleEndian.Uint32(msg)

	if protoId != SMB2_PROTO_ID {
		panic(fmt.Errorf("Unknown protocol_id %x", protoId))
	}
	structureSize := binary.LittleEndian.Uint16(msg[4:])

	if structureSize != 64 {
		panic(fmt.Errorf("Wrong size of header %d", structureSize))
	}

	// ignore CreditCharge

	/*
		creditRequest := binary.LittleEndian.Uint16(msg[14:])
		if creditRequest != 0 {
			fmt.Printf("%v: Warn creditRequest %v\n", conn.remoteAddr, creditRequest)
		}*/

	command := binary.LittleEndian.Uint16(msg[12:])
	//flags := binary.LittleEndian.Uint32(msg[16:])
	nextCommand := binary.LittleEndian.Uint32(msg[20:])
	messageId := int64(binary.LittleEndian.Uint64(msg[24:]))

	if nextCommand != 0 {
		panic(fmt.Errorf("NextCommand(%d) != 0", nextCommand))
	}

	if messageId <= conn.lastMessageId {
		panic(fmt.Errorf("Invalid MessageId = %d", messageId))
	}

	conn.lastMessageId = messageId
	conn.lastProcId = binary.LittleEndian.Uint32(msg[32:])

	channelSequence := binary.LittleEndian.Uint32(msg[8:])
	if channelSequence != 0 {
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	if command == SMB2_NEGOTIATE {
		conn.handleNegotiate(msg)
	} else if command == SMB2_SESSION_SETUP {
		conn.handleSessionSetup(msg)
	} else if command == SMB2_ECHO {
		var resp SMB2_ECHO_Response
		resp.Header.CreditResponse = 1
		resp.Header.Command = SMB2_ECHO
		resp.StructureSize = 4
		conn.writeSimpleResponse(resp)
	} else {
		sessionId := binary.LittleEndian.Uint64(msg[40:])
		if s, ok := conn.sessions[sessionId]; ok {
			switch command {
			case SMB2_LOGOFF:
				conn.handleCloseSession(s, msg)
			case SMB2_TREE_CONNECT:
				s.handleTreeConnect(conn, msg)
			case SMB2_TREE_DISCONNECT:
				s.handleTreeDisconnect(conn, msg)
			case SMB2_CREATE:
				s.handleCreate(conn, msg)
			case SMB2_CLOSE:
				s.handleClose(conn, msg)
			case SMB2_FLUSH:
				s.handleFlush(conn, msg)
			case SMB2_READ:
				s.handleRead(conn, msg)
			case SMB2_WRITE:
				s.handleWrite(conn, msg)
			case SMB2_QUERY_DIRECTORY:
				s.handleQueryDirectory(conn, msg)
			case SMB2_QUERY_INFO:
				s.handleQueryInfo(conn, msg)
			default:
				conn.writeErrorResponse(STATUS_NOT_IMPLEMENTED, msg)
			}
		} else {
			conn.writeErrorResponse(STATUS_USER_SESSION_DELETED, msg)
		}
	}
}

func (conn *Connection) writeSimpleResponse(resp interface{}) {
	err := conn.writeResponse(func(w *bytes.Buffer) {
		binary.Write(w, binary.LittleEndian, resp)
	})
	if err != nil {
		panic(err)
	}
}

var zeroBytes [128]byte
var emptyErrorResponse = []byte{9, 0, 0, 0, 0, 0, 0, 0, 0}

func (conn *Connection) writeErrorResponse(errorCode uint32, request []byte) {

	fmt.Printf("ERROR: %s reply error %x\n", conn.remoteAddr, errorCode)

	err := conn.writeResponse(func(w *bytes.Buffer) {

		//command := binary.LittleEndian.Uint16(request[12:])

		startOffset := w.Len()
		// Copy header back
		w.Write(request[6:SMB2_HEADER_SIZE]) // skip ProtocolId and StructureSize

		binary.LittleEndian.PutUint32(w.Bytes()[startOffset+2:], errorCode) // Header.Status = errorCode

		w.Write(emptyErrorResponse)
	})
	if err != nil {
		panic(err)
	}
}

// panics if cannot write into buffer
func (conn *Connection) writeResponse(cb func(w *bytes.Buffer)) error {

	// transport_frame_header + header.ProtocolId + header.StructureSize
	var transport_frame_header [10]byte

	conn.writeBuf.Reset()
	conn.writeBuf.Write(transport_frame_header[:])

	cb(&conn.writeBuf)

	buf := conn.writeBuf.Bytes()

	sz := len(buf) - 4

	if sz > maxTransactSize {
		panic(fmt.Errorf("Too long response size %v", sz))
	}
	if sz < 64 {
		panic(fmt.Errorf("Too short message %v", sz))
	}

	binary.BigEndian.PutUint32(buf, uint32(sz))

	hdr := buf[4:]
	binary.LittleEndian.PutUint64(hdr[:], SMB2_PROTO_ID)
	binary.LittleEndian.PutUint32(hdr[4:], 64) // header StructureSize
	binary.LittleEndian.PutUint64(hdr[24:], uint64(conn.lastMessageId))
	binary.LittleEndian.PutUint32(hdr[32:], conn.lastProcId)

	hdr[16] |= 1 // set SMB2_FLAGS_SERVER_TO_REDIR

	for len(buf) > 0 {
		n, err := conn.fp.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}

	fmt.Printf("DEBUG: %s %d replyed\n", conn.remoteAddr, conn.writeBuf.Len())
	return nil
}

// Handles incoming requests.
func HandleConnection(conn net.Conn, openUserCallback func(user *User) ([]Tree, error)) {

	remoteAddr := conn.RemoteAddr()

	defer func() {
		if err := recover(); err != nil {
			b := make([]byte, 4000, 4000)
			n := runtime.Stack(b, false)
			fmt.Printf("Error(%v): %s\n\n", remoteAddr, err)
			fmt.Printf("%s\n", b[:n])
		}
	}()

	defer conn.Close()

	fmt.Printf("Connected from %v\n", conn.RemoteAddr())

	buf := make([]byte, maxTransactSize+4000)

	buf_end := 0

	pc := &Connection{
		state:            stateCreated,
		remoteAddr:       remoteAddr,
		lastMessageId:    -1,
		fp:               conn,
		preauth_sessions: make(map[uint64]*Session),
		sessions:         make(map[uint64]*Session),
		openUserCallback: openUserCallback,
	}

	for {

		n, err := conn.Read(buf[buf_end:])

		if err == io.EOF && n == 0 {
			fmt.Printf("%v: remote host closed connection\n", conn.RemoteAddr())
			return
		}

		if err != nil && err != io.EOF {
			fmt.Printf("Error(%v): %v %s\n", conn.RemoteAddr(), buf_end, err)
			return
		}

		buf_end += n

		if buf_end >= 68 {
			if buf[0] != 0 {
				fmt.Printf("Unknown transport message type %v\n", buf[0])
				return
			}
			sz := int(binary.BigEndian.Uint32(buf[:]))

			if sz+4 <= buf_end {
				//fmt.Printf("handle %v\n", buf[4])
				pc.handleSMB2Message(buf[4 : 4+sz])
				buf_end -= sz + 4
			}
		} else {
			fmt.Printf("small buffer %v\n", buf_end)
		}
	}
}
