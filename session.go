package smb2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type fileInfo struct {
	isDir       bool
	dentries    []Stat
	nEnumerated int
	name        string
}

// See 3.2.1.3 page 137
type Session struct {
	id uint64 // const

	treesById   map[uint32]Tree
	treesByName map[string]Tree

	openedFiles map[GUID]*fileInfo
}

func NewSession() *Session {

	return &Session{
		id:          uint64(time.Now().UnixNano()),
		treesById:   make(map[uint32]Tree),
		treesByName: make(map[string]Tree),
		openedFiles: make(map[GUID]*fileInfo),
	}
}

func (session *Session) addTrees(trees []Tree) {
	for _, p := range trees {
		session.treesById[p.Id()] = p
		session.treesByName[p.Name()] = p
	}
}

// [MS-FSCC].pdf 2.4.1 page 105
func addFileAccessInformation(dst []byte, fi Stat) []byte {
	binary.LittleEndian.PutUint32(dst, GENERIC_ALL) // TODO: implement correctly
	return dst[4:]
}

func toFileAttributes(fi Stat) uint32 {
	var fileAttributes uint32

	if fi.IsDir() {
		fileAttributes |= FILE_ATTRIBUTE_DIRECTORY
	}

	if fi.IsReadOnly() {
		fileAttributes |= FILE_ATTRIBUTE_READONLY
	}

	return fileAttributes
}

// [MS-FSCC].pdf 2.4.7 page 110
func addFileBasicInformation(dst []byte, fi Stat) []byte {

	mtime := uint64(timeToFiletime(fi.ModTime()))
	atime := uint64(0) // uint64(timeToFiletime(statAccessTime(fi)))

	binary.LittleEndian.PutUint64(dst, mtime)      // CreationTime
	binary.LittleEndian.PutUint64(dst[8:], atime)  // LastAccessTime
	binary.LittleEndian.PutUint64(dst[16:], mtime) // LastWriteTime
	binary.LittleEndian.PutUint64(dst[24:], mtime) // ChangeTime

	binary.LittleEndian.PutUint32(dst[32:], toFileAttributes(fi))
	return dst[40:]
}

// [MS-FSCC].pdf 2.4.38 page 159
func addFileStandardInformation(dst []byte, fi Stat) []byte {
	binary.LittleEndian.PutUint64(dst, 1024*1024)             // AllocationTime
	binary.LittleEndian.PutUint64(dst[8:], uint64(fi.Size())) // EndOfFile
	binary.LittleEndian.PutUint32(dst[16:], 1)                // NumberOfLinks
	if fi.IsDir() {
		dst[21] = 1
	}
	return dst[24:]
}

// [MS-FSCC].pdf 2.4.20 page 134
func addFileInternalInformation(dst []byte, fi Stat) []byte {
	// IndexNumber is not supported
	return dst[8:]
}

// [MS-FSCC].pdf 2.4.12 page 118
func addFileEaInformation(dst []byte, fi Stat) []byte {
	// Extented attiributes are not supported
	return dst[4:]
}

// [MS-FSCC].pdf 2.4.32 page 150
func addFilePositionInformation(dst []byte, tree Tree, fp FileId) []byte {
	pos := tree.CurrentPosition(fp)
	binary.LittleEndian.PutUint64(dst[:], uint64(pos))
	return dst[8:]
}

// [MS-FSCC].pdf 2.4.24 page 139
func addFileModeInformation(dst []byte) []byte {
	dst[0] = 0x10 // FILE_SYNCHRONOUS_IO_ALERT
	return dst[4:]
}

// [MS-FSCC].pdf 2.4.3
func addFileAligmentInformation(dst []byte) []byte {
	// zero means byte alignment
	return dst[4:]
}

// [MS-FSCC].pdf 2.1.7 page 26
func addFileNameInformation(dst []byte, fi Stat) []byte {

	u16name := stringToUtf16le(fi.Name())
	binary.LittleEndian.PutUint32(dst, uint32(len(u16name)))
	copy(dst[4:], u16name)
	return dst[4+len(u16name):]
}

// [MS-SMB2].pdf 3.3.5.20 page 323
func (session *Session) handleQueryInfo(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_QUERY_INFO %d request\n", conn.remoteAddr, conn.lastMessageId)

	flags := binary.LittleEndian.Uint32(msg[16:])

	if flags&^SMB2_FLAGS_PRIORITY_MASK != 0 {
		conn.writeErrorResponse(STATUS_NOT_IMPLEMENTED, msg)
		fmt.Printf("ERROR: %s QueryInfo with flags %x", conn.remoteAddr, flags)
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 41 {
		fmt.Printf("Wrong size of header %d", structureSize)
		conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
		return
	}

	infoType := req[2]
	fileInfoClass := req[3]
	maxResponseSize := binary.LittleEndian.Uint32(req[4:])

	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]

	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	// page 125
	var resp SMB2_QUERY_INFO_Response_Header

	resp.Header.Command = SMB2_QUERY_INFO
	resp.Header.SessionId = session.id
	resp.Header.TreeId = treeId
	resp.StructureSize = 9
	resp.OutputBufferOffset = 64 + 8
	resp.Header.CreditResponse = 2

	var qinfo_buf [6000]byte
	var qinfo []byte

	if infoType == SMB2_O_INFO_FILESYSTEM {

		switch fileInfoClass {
		case FS_ATTRIBUTE_INFORMATION:
			qinfo = qinfo_buf[:20]
			binary.LittleEndian.PutUint32(qinfo[:], FILE_CASE_SENSITIVE_SEARCH|FILE_CASE_PRESERVED_NAMES|FILE_UNICODE_ON_DISK)
			//binary.LittleEndian.PutUint32(qinfo[:], 0x1006f)
			binary.LittleEndian.PutUint32(qinfo[4:], 255)                           // MaximumComponentNameLength
			copy(qinfo[8:], []byte{8, 0, 0, 0, 0x4e, 0, 0x54, 0, 0x46, 0, 0x53, 0}) // NTFS fs name
		case FS_DEVICE_INFORMATION:
			qinfo = qinfo_buf[:8]
			copy(qinfo[:], []byte{7, 0, 0, 0, 0x20, 0, 0, 0}) // 0x22 if read only
		case FS_SECTOR_SIZE_INFORMATION:
			qinfo = qinfo_buf[:28]
			// See [MS-FSCC].pdf 2.5.7 page 173
			copy(qinfo[:], []byte{0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		default:
			conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
			return
		}
	} else if infoType == SMB2_O_INFO_FILE {

		var guid GUID
		copy(guid[:], req[24:])

		if _, ok := session.openedFiles[guid]; ok {

			fp := guid.fileId()
			fi, err := tree.StatById(fp, true)

			if err != nil {
				conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
				return
			}
			qinfo = qinfo_buf[:]

			switch fileInfoClass {
			case FILE_ALL_INFORMATION:
				qinfo = addFileBasicInformation(qinfo, fi)
				qinfo = addFileStandardInformation(qinfo, fi)
				qinfo = addFileInternalInformation(qinfo, fi)
				qinfo = addFileEaInformation(qinfo, fi)
				qinfo = addFileAccessInformation(qinfo, fi)
				qinfo = addFilePositionInformation(qinfo, tree, fp)
				qinfo = addFileModeInformation(qinfo)
				qinfo = addFileAligmentInformation(qinfo)
				qinfo = addFileNameInformation(qinfo, fi)
			default:
				conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
				return
			}

			totalSize := len(qinfo_buf) - len(qinfo)
			qinfo = qinfo_buf[:totalSize]
		} else {
			conn.writeErrorResponse(STATUS_FILE_CLOSED, msg)
			return
		}
	} else {
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	resp.OutputBufferLength = uint32(len(qinfo))

	if len(qinfo) > int(maxResponseSize) {
		conn.writeErrorResponse(STATUS_INFO_LENGTH_MISMATCH, msg)
		return

	}

	err := conn.writeResponse(func(w *bytes.Buffer) {
		binary.Write(w, binary.LittleEndian, &resp)
		w.Write(qinfo)
	})

	if err != nil {
		panic(err)
	}
}

func (session *Session) handleTreeConnect(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_TREE_CONNECT request\n", conn.remoteAddr)

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 9 {
		panic(fmt.Errorf("StructureSize == %d", structureSize))
	}

	if req[2] != 0 {
		panic(fmt.Errorf("Session binding is not supported"))
	}

	pathOffset := binary.LittleEndian.Uint16(req[4:])
	pathLength := binary.LittleEndian.Uint16(req[6:])

	if pathOffset != 64+8 {
		panic(fmt.Errorf("PathOffset == %d", pathOffset))
	}

	tname := utf16leToString(msg[pathOffset : pathOffset+pathLength])

	if tname[0] != '\\' || tname[1] != '\\' {
		panic(fmt.Errorf("invalid sdsdfsf '%s'", tname))
	}

	tname = tname[2:]

	inx := strings.IndexByte(tname, '\\')
	if inx < 0 {
		panic(fmt.Errorf("invalid sdsdfsf43"))
	}

	tname = tname[inx+1:]

	if t, ok := session.treesByName[tname]; ok {

		var resp SMB2_TREE_CONNECT_Response_Header

		resp.Header.CreditResponse = 1
		resp.Header.Command = SMB2_TREE_CONNECT
		resp.Header.SessionId = session.id
		resp.Header.TreeId = t.Id()

		resp.StructureSize = 16
		resp.MaximalAccess = 0x81 // ReadOnly
		resp.ShareType = 1

		err := conn.writeResponse(func(w *bytes.Buffer) {

			binary.Write(w, binary.LittleEndian, &resp)

		})

		delete(conn.preauth_sessions, session.id)

		if err != nil {
			panic(err)
		}
	} else {
		panic(fmt.Errorf("unknown tree '%s'", tname))
	}
}

func (session *Session) handleTreeDisconnect(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_TREE_DISCONNECT request\n", conn.remoteAddr)

	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]

	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	for guid, f := range session.openedFiles {
		if guid.treeId() == treeId {
			fmt.Printf("Force close %s\n", f.name)
			tree.CloseFile(guid.fileId())
			delete(session.openedFiles, guid)
		}
	}

	var resp SMB2_TREE_DISCONNECT_Response
	resp.Header.CreditResponse = 1
	resp.Header.Command = SMB2_TREE_DISCONNECT
	resp.StructureSize = 4
	conn.writeSimpleResponse(resp)
}

// [MS-SMB2].pdf 3.3.5.9 page 275
func (session *Session) handleCreate(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_CREATE request\n", conn.remoteAddr)

	flags := binary.LittleEndian.Uint32(msg[16:])

	if flags&^SMB2_FLAGS_PRIORITY_MASK != 0 {
		fmt.Printf("ERROR: %s SessionSetup with flags %x", conn.remoteAddr, flags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 57 {
		panic(fmt.Errorf("Wrong size of header %d", structureSize))
	}
	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]

	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	/*
		requestedOplockLevel := req[3]

		if requestedOplockLevel != 0 {
			fmt.Printf("ERROR: %s oplocl not implemented %d", conn.remoteAddr, requestedOplockLevel)
			conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
			return
		}*/

	desiredAccess := binary.LittleEndian.Uint32(req[24:])
	//fileAttributes := binary.LittleEndian.Uint32(req[28:])
	//shareAccess := binary.LittleEndian.Uint32(req[32:])
	createDisposition := binary.LittleEndian.Uint32(req[36:])
	//createOptions := binary.LittleEndian.Uint32(req[40:]) // page 58
	nameOffset := binary.LittleEndian.Uint16(req[44:])
	nameLength := binary.LittleEndian.Uint16(req[46:])

	// See 3.2.4.4 re-establishing a durable open. page 156
	/*
		createContextsLength := binary.LittleEndian.Uint32(req[52:])
			if createContextsLength != 0 {
				fmt.Printf("ERROR: %s CreateContextsLength not implemented %d", conn.remoteAddr, createContextsLength)
				conn.writeErrorResponse(STATUS_NOT_IMPLEMENTED, msg)
				return
			}*/

	path := utf16leToString(msg[nameOffset : nameOffset+nameLength])

	path = strings.Replace(path, "\\", "/", -1)

	openFlags := 0
	switch createDisposition {
	case FILE_SUPERSEDE:
		openFlags = os.O_TRUNC | os.O_CREATE | os.O_RDWR
	case FILE_OPEN:
	case FILE_CREATE:
		openFlags = os.O_EXCL | os.O_RDWR
	case FILE_OPEN_IF:
		openFlags = os.O_CREATE
	case FILE_OVERWRITE:
		openFlags = os.O_TRUNC
	case FILE_OVERWRITE_IF:
		openFlags = os.O_TRUNC | os.O_CREATE | os.O_RDWR
	default:
		fmt.Printf("ERROR: %s create disposition %d", conn.remoteAddr, createDisposition)
		conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
		return
	}

	if desiredAccess&(FILE_WRITE_DATA|GENERIC_ALL|GENERIC_WRITE) != 0 {
		openFlags |= os.O_RDWR
	} else if openFlags&os.O_RDWR == 0 {
		openFlags |= os.O_RDONLY
	}

	fp, err := tree.OpenFile(path, openFlags)

	if os.IsNotExist(err) {
		fmt.Printf("ERROR: %s %s\n", conn.remoteAddr, err)
		conn.writeErrorResponse(STATUS_OBJECT_NAME_NOT_FOUND, msg)
		return
	}

	if err != nil {
		fmt.Printf("ERROR: %s %s\n", conn.remoteAddr, err)
		conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
		return
	}

	fi, err := tree.StatById(fp, false)

	if err != nil {
		fmt.Printf("ERROR: %s %s\n", conn.remoteAddr, err)
		conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
		return
	}

	guid := makeGUID(treeId, fp)

	if fi.IsDir() {
		session.openedFiles[guid] = &fileInfo{isDir: true, name: fi.Name()}
	} else {
		session.openedFiles[guid] = &fileInfo{name: fi.Name()}
	}

	// page 73
	var resp SMB2_CREATE_Response_Header

	resp.Header.CreditResponse = 1
	resp.Header.Command = SMB2_CREATE
	resp.Header.SessionId = session.id
	resp.Header.TreeId = treeId
	resp.StructureSize = 89
	resp.FileId = guid

	mtime := timeToFiletime(fi.ModTime())
	resp.CreationTime = mtime
	resp.LastWriteTime = mtime
	resp.ChangeTime = mtime
	resp.LastAccessTime = 0 // timeToFiletime(statAccessTime(fi))

	if fi.IsDir() {
		resp.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY
	} else {
		resp.EndOfFile = uint64(fi.Size())
		resp.AllocationSize = 1024 * 1024
	}

	err = conn.writeResponse(func(w *bytes.Buffer) {
		binary.Write(w, binary.LittleEndian, &resp)
	})

	if err != nil {
		tree.CloseFile(fp)
		delete(session.openedFiles, guid)
		panic(err)
	}
}

// [MS-SMB2].pdf 3.3.5.10 page 294
func (session *Session) handleClose(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_CLOSE request\n", conn.remoteAddr)

	flags := binary.LittleEndian.Uint32(msg[16:])

	if flags&^SMB2_FLAGS_PRIORITY_MASK != 0 {
		fmt.Printf("ERROR: %s SessionSetup with flags %x", conn.remoteAddr, flags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 24 {
		panic(fmt.Errorf("Wrong size of header %d", structureSize))
	}
	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]
	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	var guid GUID
	copy(guid[:], req[8:])

	if _, ok := session.openedFiles[guid]; ok {

		fp := guid.fileId()

		var resp SMB2_CLOSE_Response

		if req[2]&1 == 1 { // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB

			fi, err := tree.StatById(fp, false)

			if err == nil {

				mtime := timeToFiletime(fi.ModTime())
				resp.CreationTime = mtime
				resp.LastWriteTime = mtime
				resp.ChangeTime = mtime
				resp.LastAccessTime = 0 // timeToFiletime(statAccessTime(fi))

				resp.Flags = 1

			} else {
				fmt.Printf("ERROR: %s stat '%s' %v", conn.remoteAddr, tree.NameOfFile(fp), err)
			}

		}

		tree.CloseFile(fp)
		delete(session.openedFiles, guid)

		resp.Header.CreditResponse = 1
		resp.Header.Command = SMB2_CLOSE
		resp.Header.SessionId = session.id
		resp.Header.TreeId = treeId
		resp.StructureSize = 60

		conn.writeSimpleResponse(resp)
	} else {
		conn.writeErrorResponse(STATUS_FILE_CLOSED, msg)
	}
}

// [MS-SMB2].pdf 3.3.5.11 page 295
func (session *Session) handleFlush(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_FLUSH request\n", conn.remoteAddr)

	flags := binary.LittleEndian.Uint32(msg[16:])

	if flags&^SMB2_FLAGS_PRIORITY_MASK != 0 {
		fmt.Printf("ERROR: %s SessionSetup with flags %x", conn.remoteAddr, flags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 24 {
		panic(fmt.Errorf("Wrong size of header %d", structureSize))
	}
	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]
	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	var guid GUID
	copy(guid[:], req[8:])

	if _, ok := session.openedFiles[guid]; !ok {
		conn.writeErrorResponse(STATUS_FILE_CLOSED, msg)
		return
	}

	fp := guid.fileId()

	err := tree.Sync(fp)
	if err != nil {
		fmt.Printf("ERROR: %s sync '%s' %s", conn.remoteAddr, tree.NameOfFile(fp), err)
	}
	var resp SMB2_FLUSH_Response
	resp.Header.CreditResponse = 1
	resp.Header.Command = SMB2_FLUSH
	resp.Header.SessionId = session.id
	resp.Header.TreeId = treeId
	resp.StructureSize = 4

	conn.writeSimpleResponse(resp)
}

// [MS-SMB2].pdf 3.3.5.12 page 296
func (session *Session) handleRead(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_READ request\n", conn.remoteAddr)

	flags := binary.LittleEndian.Uint32(msg[16:])

	if flags&^SMB2_FLAGS_PRIORITY_MASK != 0 {
		fmt.Printf("ERROR: %s read with flags %x", conn.remoteAddr, flags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 49 {
		panic(fmt.Errorf("Wrong size of header %d", structureSize))
	}
	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]
	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	var guid GUID
	copy(guid[:], req[16:])

	if _, ok := session.openedFiles[guid]; !ok {
		conn.writeErrorResponse(STATUS_FILE_CLOSED, msg)
		return
	}

	fp := guid.fileId()

	length := binary.LittleEndian.Uint32(req[4:])
	offset := binary.LittleEndian.Uint64(req[8:])
	minimumCount := binary.LittleEndian.Uint32(req[32:])
	channel := binary.LittleEndian.Uint32(req[36:])
	// TODO: use for read-ahead
	// remainingBytes := binary.LittleEndian.Uint32(req[40:])

	if length > maxTransactSize || length == 0 {
		conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
		return
	}

	if channel != 0 {
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	buffer := make([]byte, length)

	err := tree.Seek(fp, int64(offset))
	if err != nil {
		conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
		return
	}

	n, err := tree.Read(fp, buffer)

	if n < int(minimumCount) {
		conn.writeErrorResponse(STATUS_END_OF_FILE, msg)
		return
	}

	if err != nil && err != io.EOF {
		conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
		return
	}

	var resp SMB2_READ_Response_Header

	resp.Header.CreditResponse = 1
	resp.Header.Command = SMB2_READ
	resp.Header.SessionId = session.id
	resp.Header.TreeId = treeId
	resp.StructureSize = 17
	resp.DataOffset = 80
	resp.DataLength = uint32(n)
	err = conn.writeResponse(func(w *bytes.Buffer) {
		binary.Write(w, binary.LittleEndian, &resp)
		w.Write(buffer[:n])
	})
	if err != nil {
		panic(err)
	}
}

// [MS-SMB2].pdf 3.3.5.13 page 298
func (session *Session) handleWrite(conn *Connection, msg []byte) {

	fmt.Printf("DEBUG: %s SMB2_WRITE request\n", conn.remoteAddr)

	flags := binary.LittleEndian.Uint32(msg[16:])

	if flags&^SMB2_FLAGS_PRIORITY_MASK != 0 {
		fmt.Printf("ERROR: %s read with flags %x", conn.remoteAddr, flags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 49 {
		panic(fmt.Errorf("Wrong size of header %d", structureSize))
	}
	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]
	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	var guid GUID
	copy(guid[:], req[16:])

	if _, ok := session.openedFiles[guid]; !ok {
		conn.writeErrorResponse(STATUS_FILE_CLOSED, msg)
		return
	}

	fp := guid.fileId()

	dataOffset := binary.LittleEndian.Uint16(req[2:])
	length := binary.LittleEndian.Uint32(req[4:])
	offset := binary.LittleEndian.Uint64(req[8:])
	channel := binary.LittleEndian.Uint32(req[32:])
	//flags := binary.LittleEndian.Uint32(req[44:])

	if length > maxTransactSize || length == 0 {
		conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
		return
	}

	if channel != 0 {
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	buffer := msg[dataOffset:]

	if len(buffer) != int(length) {
		conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
		return
	}

	err := tree.Seek(fp, int64(offset))
	if err != nil {
		conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
		return
	}

	_, err = tree.Write(fp, buffer)

	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
		return
	}

	var resp SMB2_WRITE_Response

	resp.Header.CreditResponse = 1
	resp.Header.Command = SMB2_WRITE
	resp.Header.SessionId = session.id
	resp.Header.TreeId = treeId
	resp.StructureSize = 17
	resp.Count = length

	conn.writeSimpleResponse(resp)
}

func addBaseDirEntryInformation(dst []byte, fi Stat, utf16name []byte) {
	mtime := uint64(timeToFiletime(fi.ModTime()))
	atime := uint64(0) // uint64(timeToFiletime(statAccessTime(fi)))

	binary.LittleEndian.PutUint64(dst, mtime)                  // CreationTime
	binary.LittleEndian.PutUint64(dst[8:], atime)              // LastAccessTime
	binary.LittleEndian.PutUint64(dst[16:], mtime)             // LastWriteTime
	binary.LittleEndian.PutUint64(dst[24:], mtime)             // ChangeTime
	binary.LittleEndian.PutUint64(dst[32:], uint64(fi.Size())) // EndOfFile
	binary.LittleEndian.PutUint64(dst[40:], 1024*1024)         // AllocationTime
	binary.LittleEndian.PutUint32(dst[48:], toFileAttributes(fi))
	binary.LittleEndian.PutUint32(dst[52:], uint32(len(utf16name)))
	// total 56
}

// [MS-SMB2].pdf 3.3.5.18 page 319
func (session *Session) handleQueryDirectory(conn *Connection, msg []byte) {
	fmt.Printf("DEBUG: %s SMB2_QUERY_DIRECTORY request\n", conn.remoteAddr)
	req := msg[SMB2_HEADER_SIZE:]
	structureSize := int(binary.LittleEndian.Uint16(req))

	if structureSize != 33 {
		panic(fmt.Errorf("Wrong size of header %d", structureSize))
	}
	treeId := binary.LittleEndian.Uint32(msg[36:])

	tree, ok := session.treesById[treeId]
	if !ok {
		conn.writeErrorResponse(STATUS_NETWORK_NAME_DELETED, msg)
		return
	}

	var guid GUID
	copy(guid[:], req[8:])

	fileInfo, ok := session.openedFiles[guid]
	if !ok {
		conn.writeErrorResponse(STATUS_FILE_CLOSED, msg)
		return
	}

	fp := guid.fileId()

	reqFlags := req[3]
	fileInfoClass := req[2]

	if reqFlags&SMB2_INDEX_SPECIFIED != 0 {
		fmt.Printf("reqFlags %x\n", reqFlags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	if reqFlags&(SMB2_REOPEN|SMB2_RESTART_SCANS) != 0 {
		fmt.Printf("reqFlags %x\n", reqFlags)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	if !fileInfo.isDir {
		fmt.Printf("is not directory %s\n", fileInfo.name)
		conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
		return
	}

	fileNameOffset := binary.LittleEndian.Uint16(req[24:])
	fileNameLength := binary.LittleEndian.Uint16(req[26:])

	searchPattern := utf16leToString(msg[fileNameOffset : fileNameOffset+fileNameLength])
	outputBufferLength := binary.LittleEndian.Uint32(req[28:])

	if outputBufferLength > maxTransactSize {
		conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
		return
	}

	if searchPattern == "*" {
		searchPattern = ""
	}

	maxCount := 65536

	if reqFlags&SMB2_RETURN_SINGLE_ENTRY != 0 {
		maxCount = 1
	}

	if searchPattern != "" {
		// TODO: filepath.Match
		fmt.Printf("Search pattern %s\n", searchPattern)
		conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
		return
	}

	if outputBufferLength > 8*1024*1024 {
		outputBufferLength = 8 * 1024 * 1024
	}

	buffer := make([]byte, 0, outputBufferLength)

	tmp := make([]byte, 32000)

	prevOffset := 0
	nwritten := 0
	statBuf := fileInfo.dentries
	fileInfo.dentries = nil
	for i := 0; i < maxCount; i++ {

		var err error
		if len(statBuf) == 0 {
			statBuf, err = tree.ReadDir(fp, 100)

			if err == io.EOF {
				if len(statBuf) < 1 {
					break
				} else {
					err = nil
				}
			}
			if err != nil {
				log.Println(err)
				conn.writeErrorResponse(STATUS_UNSUCCESSFUL, msg)
				return
			}
		}

		fi := statBuf[0]

		utf16name := stringToUtf16le(fi.Name())

		switch fileInfoClass {
		case FILE_DIRECTORY_INFORMATION:
			addBaseDirEntryInformation(tmp, fi, utf16name)
			tmp = tmp[:56]
		case FILE_FULL_DIRECTORY_INFORMATION:
			addBaseDirEntryInformation(tmp, fi, utf16name)
			tmp = tmp[:56+4] // EaSize, u32

		//case FILE_NAMES_INFORMATION:
		// fileIndex u32
		// name lenght
		// name
		case FILE_ID_FULL_DIRECTORY_INFORMATION:

			addBaseDirEntryInformation(tmp, fi, utf16name)
			// EaSize u32
			// Reserved u32
			// FileId u64
			tmp = tmp[:56+4+4+8]

		case FILE_BOTH_DIRECTORY_INFORMATION, FILE_ID_BOTH_DIRECTORY_INFORMATION:
			conn.writeErrorResponse(STATUS_NOT_SUPPORTED, msg)
			return
		default:
			conn.writeErrorResponse(STATUS_INVALID_INFO_CLASS, msg)
			return
		}

		if cap(buffer)-len(buffer) > len(tmp)+len(utf16name)+8+8 {

			padding := calcPadding(len(buffer), 8)

			buffer = buffer[:len(buffer)+padding]

			if nwritten > 0 {
				binary.LittleEndian.PutUint32(buffer[prevOffset:], uint32(len(buffer)-prevOffset))
			}
			prevOffset = len(buffer)

			buffer = buffer[:len(buffer)+8] // NextEntryOffset, FileIndex
			buffer = append(buffer, tmp...)
			buffer = append(buffer, utf16name...)
			nwritten++
			statBuf = statBuf[1:]
		} else {
			fileInfo.dentries = statBuf
			break
		}
	}

	if nwritten == 0 {

		if len(fileInfo.dentries) > 0 {
			conn.writeErrorResponse(STATUS_INVALID_PARAMETER, msg)
			return
		}

		if fileInfo.nEnumerated == 0 {
			conn.writeErrorResponse(STATUS_NO_SUCH_FILE, msg)
			return
		}
		conn.writeErrorResponse(STATUS_NO_MORE_FILES, msg)
		return
	} else {
		fileInfo.nEnumerated += nwritten

		var resp SMB2_QUERY_DIRECTORY_Response_Header
		resp.Header.Command = SMB2_QUERY_DIRECTORY
		resp.Header.SessionId = session.id
		resp.Header.TreeId = treeId
		resp.StructureSize = 9
		resp.OutputBufferOffset = 64 + 8
		resp.Header.CreditResponse = 2
		resp.OutputBufferLength = uint32(len(buffer))

		err := conn.writeResponse(func(w *bytes.Buffer) {
			binary.Write(w, binary.LittleEndian, &resp)
			w.Write(buffer)
		})
		if err != nil {
			panic(err)
		}
	}
}

func (session *Session) Close() {

	for guid, f := range session.openedFiles {
		fmt.Printf("Force close %s\n", f.name)
		if tree, ok := session.treesById[guid.treeId()]; ok {
			tree.CloseFile(guid.fileId())
		}
	}

	session.openedFiles = nil
}
