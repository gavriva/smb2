package smb2

import "encoding/binary"

type GUID [16]byte

func (g GUID) fileId() FileId {
	return FileId(binary.LittleEndian.Uint64(g[8:]))
}

func (g GUID) treeId() uint32 {
	return binary.LittleEndian.Uint32(g[:])
}

func makeGUID(treeId uint32, fid FileId) GUID {
	var guid GUID
	binary.LittleEndian.PutUint64(guid[:], uint64(treeId))
	binary.LittleEndian.PutUint64(guid[8:], uint64(fid))
	return guid
}

/*
type SMB2_Request_Header struct {
	ProtocolId      uint32 // The value MUST be (in network order) 0xFE, 'S', 'M' and 'B'.
	StructureSize   uint16 // must be 64
	CreditCharge    uint16
	ChannelSequence uint16
	Reserved        uint16
	Command         uint16
	CreditRequest   uint16
	Flags           uint32
	NextCommand     uint32
	MessageId       uint64
	Reserved2       uint32 // AsyncId
	TreeId          uint32 // AsyncId
	SessionId       uint64
	Signature       [2]uint64
}
*/

type SMB2_Response_Header struct {
	// First two fields are written by Connection.writeResponse
	//ProtocolId     uint32 // The value MUST be (in network order) 0xFE, 'S', 'M' and 'B'.
	//StructureSize  uint16 // must be 64
	CreditCharge   uint16
	Status         uint32
	Command        uint16
	CreditResponse uint16
	Flags          uint32
	NextCommand    uint32
	MessageId      int64
	Reserved       uint32 // AsyncId
	TreeId         uint32 // AsyncId
	SessionId      uint64
	Signature      [2]uint64
}

type SMB2_ERROR_Response struct {
	Header            SMB2_Response_Header
	StructureSize     uint16
	ErrorContextCount uint8
	Reserved          uint8
	ByteCount         uint32
	ErrorData         []SMB2_ERROR_Context_Response
}

type SMB2_ERROR_Context_Response struct {
	ErrorDataLength  uint32
	ErrorId          uint32
	ErrorContextData []byte
}

/*
type SMB2_NEGOTIATE_Request struct {
	Header        SMB2_Request_Header
	StructureSize uint16
	DialectCount  uint16
	SecurityMode  uint16
	Reserved      uint16
	Capabilities  uint32
	ClientGuid    GUID
	// If the Dialects field doesn't contain 0x0311, this field is interpreted as the ClientStartTime(uint64) field.
	NegotiateContextOffset uint32
	NegotiateContextCount  uint16
	Reserved2              uint16
	Dialects               []uint16
	// Padding
	NegotiateContextList []interface{}
}
*/

/*
type SMB2_PREAUTH_INTEGRITY_CAPABILITIES struct {
	HashAlgorithmCount uint16
	SaltLength         uint16
	HashAlgorithms     []uint16 // 0x0001 - SHA-512
	Salt               []byte
}

type SMB2_ENCRYPTION_CAPABILITIES struct {
	CipherCount uint16
	Ciphers     []uint16 // 0x0001 - AES-128-CCM, 0x0002 AES-128-GCM
}
*/

type SMB2_NEGOTIATE_Response_Header struct {
	Header                 SMB2_Response_Header
	StructureSize          uint16
	SecurityMode           uint16 // SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2_NEGOTIATE_SIGNING_REQUIRED
	DialectRevision        uint16
	NegotiateContextCount  uint16
	ServerGuid             GUID
	Capabilities           uint32
	MaxTransactSize        uint32
	MaxReadSize            uint32
	MaxWriteSize           uint32
	SystemTime             int64
	ServerStartTime        int64
	SecurityBufferOffset   uint16
	SecurityBufferLength   uint16
	NegotiateContextOffset uint32
}

type SMB2_SESSION_SETUP_Response_Header struct {
	Header               SMB2_Response_Header
	StructureSize        uint16
	SessionFlags         uint16
	SecurityBufferOffset uint16
	SecurityBufferLength uint16
}

type SMB2_LOGOFF_Response struct {
	Header        SMB2_Response_Header
	StructureSize uint16
	Reserved      uint16
}

type SMB2_TREE_CONNECT_Response_Header struct {
	Header        SMB2_Response_Header
	StructureSize uint16
	ShareType     uint8
	Reserved      uint8
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

type SMB2_TREE_DISCONNECT_Response struct {
	Header        SMB2_Response_Header
	StructureSize uint16
	Reserved      uint16
}

type SMB2_CREATE_Response_Header struct {
	Header               SMB2_Response_Header
	StructureSize        uint16
	OplockLevel          uint8
	Flags                uint8
	CreateAction         uint32
	CreationTime         int64
	LastAccessTime       int64
	LastWriteTime        int64
	ChangeTime           int64
	AllocationSize       uint64
	EndOfFile            uint64
	FileAttributes       uint32
	Reserved2            uint32
	FileId               GUID
	CreateContextsOffset uint32
	CreateContextsLength uint32
}

type SMB2_CLOSE_Response struct {
	Header         SMB2_Response_Header
	StructureSize  uint16
	Flags          uint16
	Reserved       uint32
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	AllocationSize uint64
	EndOfFile      uint64
	FileAttributes uint32
}

type SMB2_FLUSH_Response struct {
	Header        SMB2_Response_Header
	StructureSize uint16
	Reserved      uint16
}

type SMB2_READ_Response_Header struct {
	Header        SMB2_Response_Header
	StructureSize uint16
	DataOffset    uint8
	Reserved      uint8
	DataLength    uint32
	DataRemaining uint32
	Reserved2     uint32
}

type SMB2_WRITE_Response struct {
	Header                 SMB2_Response_Header
	StructureSize          uint16
	Reserved               uint16
	Count                  uint32
	Remaining              uint32
	WriteChannelInfoOffset uint16
	WriteChannelInfoLength uint16
}

type SMB2_QUERY_DIRECTORY_Response_Header struct {
	Header             SMB2_Response_Header
	StructureSize      uint16
	OutputBufferOffset uint16
	OutputBufferLength uint32
}

type SMB2_QUERY_INFO_Response_Header struct {
	Header             SMB2_Response_Header
	StructureSize      uint16
	OutputBufferOffset uint16
	OutputBufferLength uint32
}

type SMB2_ECHO_Response struct {
	Header        SMB2_Response_Header
	StructureSize uint16
	Reserved      uint16
}
