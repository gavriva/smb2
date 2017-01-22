package plain

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gavriva/smb2"
)

type Tree struct {
	name        string
	id          uint32
	baseDirPath string

	openedFiles map[smb2.FileId]*os.File
	lastFileId  smb2.FileId
}

func (tree *Tree) Name() string {
	return tree.name
}

func (tree *Tree) Id() uint32 {
	return tree.id
}

func (tree *Tree) Close() error {
	return nil
}

func CreateTree(id uint32, name string, dirpath string) (*Tree, error) {

	return &Tree{
		name:        name,
		id:          id,
		baseDirPath: dirpath,
		openedFiles: make(map[smb2.FileId]*os.File),
		lastFileId:  10,
	}, nil
}

func (tree *Tree) OpenFile(path string, flags int) (smb2.FileId, error) {
	f, err := os.OpenFile(fmt.Sprintf("%s/%s", tree.baseDirPath, path), flags, 0666)
	if err != nil {
		return 0, err
	}
	tree.lastFileId++
	tree.openedFiles[tree.lastFileId] = f
	return tree.lastFileId, nil
}

func (tree *Tree) CloseFile(fp smb2.FileId) error {
	if f, ok := tree.openedFiles[fp]; ok {
		delete(tree.openedFiles, fp)
		f.Close()
		return nil
	}
	return fmt.Errorf("Cannot close unknown file with id %d", fp)
}

func (tree *Tree) NameOfFile(fp smb2.FileId) string {
	if f, ok := tree.openedFiles[fp]; ok {
		return f.Name()
	}
	return "[unknown]"
}

var unknownFile = errors.New("Unknown file")

func (tree *Tree) StatById(fp smb2.FileId, followLinks bool) (smb2.Stat, error) {
	if f, ok := tree.openedFiles[fp]; ok {
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		return &Stat{st}, err
	}
	return nil, unknownFile
}

func (tree *Tree) Read(id smb2.FileId, p []byte) (n int, err error) {
	if f, ok := tree.openedFiles[id]; ok {
		return f.Read(p)
	}
	return 0, unknownFile
}

func (tree *Tree) Write(id smb2.FileId, p []byte) (n int, err error) {
	if f, ok := tree.openedFiles[id]; ok {
		return f.Write(p)
	}
	return 0, unknownFile
}

func (tree *Tree) Seek(id smb2.FileId, offset int64) error {
	if f, ok := tree.openedFiles[id]; ok {
		_, err := f.Seek(offset, os.SEEK_SET)
		return err
	}
	return unknownFile
}

func (tree *Tree) CurrentPosition(id smb2.FileId) int64 {
	if f, ok := tree.openedFiles[id]; ok {
		off, _ := f.Seek(0, os.SEEK_CUR)
		return off
	}
	return 0
}

func (tree *Tree) ReadDir(id smb2.FileId, n int) ([]smb2.Stat, error) {
	if f, ok := tree.openedFiles[id]; ok {
		r, err := f.Readdir(n)
		if err != nil {
			return nil, err
		}

		r2 := make([]smb2.Stat, len(r))
		for i := 0; i < len(r); i++ {
			r2[i] = Stat{r[i]}
		}
		return r2, nil
	}

	return nil, unknownFile
}

func (tree *Tree) Mkdir(path string) error {
	return os.Mkdir(fmt.Sprintf("%s/%s", tree.baseDirPath, path), 0777)
}

func (tree *Tree) Symlink(oldname, newname string) error {
	return os.Symlink(fmt.Sprintf("%s/%s", tree.baseDirPath, oldname), fmt.Sprintf("%s/%s", tree.baseDirPath, newname))
}

func (tree *Tree) Remove(path string, recursive bool) error {
	if recursive {
		return os.RemoveAll(fmt.Sprintf("%s/%s", tree.baseDirPath, path))
	}
	return os.Remove(fmt.Sprintf("%s/%s", tree.baseDirPath, path))
}

func (tree *Tree) Truncate(id smb2.FileId, size int64) error {
	if f, ok := tree.openedFiles[id]; ok {
		return f.Truncate(size)
	}
	return unknownFile
}

func (tree *Tree) ChangeMode(id smb2.FileId, allowWrite bool, allowExecute bool) error {
	return nil
}

func (tree *Tree) Sync(fp smb2.FileId) error {
	if f, ok := tree.openedFiles[fp]; ok {
		return f.Sync()
	}
	return unknownFile
}

func (tree *Tree) SyncAll() error {
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type Stat struct {
	osStat os.FileInfo
}

func (st Stat) Name() string {
	return st.osStat.Name()
}

func (st Stat) Size() int64 {
	return st.osStat.Size()
}

func (st Stat) ModTime() time.Time {
	return st.osStat.ModTime()
}

func (st Stat) IsReadOnly() bool {
	if (st.osStat.Mode().Perm() & 0333) == 0 {
		return true
	}
	return false
}

func (st Stat) IsExecutable() bool {
	if (st.osStat.Mode().Perm() & 0111) == 0 {
		return true
	}
	return false
}

func (st Stat) IsDir() bool {
	return st.osStat.Mode().IsDir()
}

func (st Stat) IsLink() bool {
	if st.osStat.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return false
}

func (st Stat) Link() string {
	return "noit_implemented"
}
