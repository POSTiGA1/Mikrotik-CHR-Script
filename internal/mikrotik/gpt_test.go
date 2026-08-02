package mikrotik

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestValidateOfficialUEFIGPTAcceptsExactHybridLayout(t *testing.T) {
	path := writeTestOfficialGPTImage(t)
	layout, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	partition, err := validateOfficialUEFIGPT(path, layout)
	if err != nil {
		t.Fatal(err)
	}
	if partition.Index != 1 || partition.StartSector != officialBootStartSector || partition.Sectors != officialBootSectors {
		t.Fatalf("unexpected boot partition: %#v", partition)
	}
}

func TestValidateOfficialUEFIGPTRejectsPartitionTableCorruption(t *testing.T) {
	path := writeTestOfficialGPTImage(t)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, int64(officialGPTPrimaryTable*sectorSize)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	layout, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateOfficialUEFIGPT(path, layout); err == nil || !strings.Contains(err.Error(), "CRC") {
		t.Fatalf("expected GPT CRC rejection, got %v", err)
	}
}

func writeTestOfficialGPTImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chr.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(officialCHRImageSectors * sectorSize)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	mbr := make([]byte, sectorSize)
	mbr[510], mbr[511] = 0x55, 0xaa
	writeTestMBRPartition(mbr[446:462], true, officialBootStartSector, officialBootSectors)
	writeTestMBRPartition(mbr[462:478], false, officialSystemStartSector, officialSystemSectors)
	if _, err := file.WriteAt(mbr, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	entries := make([]byte, officialGPTEntries*officialGPTEntrySize)
	firstUnique := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	secondUnique := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	writeTestGPTPartition(entries[:officialGPTEntrySize], efiSystemPartitionGUID, firstUnique, officialBootStartSector, officialBootStartSector+officialBootSectors-1, "RouterOS Boot")
	binary.LittleEndian.PutUint64(entries[48:56], 4)
	writeTestGPTPartition(entries[officialGPTEntrySize:2*officialGPTEntrySize], linuxFilesystemGUID, secondUnique, officialSystemStartSector, officialSystemStartSector+officialSystemSectors-1, "RouterOS")
	diskGUID := [16]byte{0x3d, 0x20, 0x52, 0x4f, 0x18, 0x8f, 0x4a, 0x84, 0x9e, 0x6b, 0x44, 0xc9, 0xa9, 0x2e, 0x60, 0xea}
	partitionCRC := crc32.ChecksumIEEE(entries)
	primary := makeTestGPTHeader(1, officialGPTBackupHeader, officialGPTPrimaryTable, diskGUID, partitionCRC)
	backup := makeTestGPTHeader(officialGPTBackupHeader, 1, officialGPTBackupTable, diskGUID, partitionCRC)
	for _, write := range []struct {
		value  []byte
		offset int64
	}{
		{mbr, 0},
		{primary, sectorSize},
		{entries, int64(officialGPTPrimaryTable * sectorSize)},
		{entries, int64(officialGPTBackupTable * sectorSize)},
		{backup, int64(officialGPTBackupHeader * sectorSize)},
	} {
		if _, err := file.WriteAt(write.value, write.offset); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestMBRPartition(entry []byte, bootable bool, start, sectors uint32) {
	if bootable {
		entry[0] = 0x80
	}
	entry[4] = 0x83
	binary.LittleEndian.PutUint32(entry[8:12], start)
	binary.LittleEndian.PutUint32(entry[12:16], sectors)
}

func writeTestGPTPartition(entry []byte, typeGUID, uniqueGUID [16]byte, first, last uint32, name string) {
	copy(entry[:16], typeGUID[:])
	copy(entry[16:32], uniqueGUID[:])
	binary.LittleEndian.PutUint64(entry[32:40], uint64(first))
	binary.LittleEndian.PutUint64(entry[40:48], uint64(last))
	encodedName := utf16.Encode([]rune(name))
	for index, value := range encodedName {
		binary.LittleEndian.PutUint16(entry[56+index*2:58+index*2], value)
	}
}

func makeTestGPTHeader(current, backup, table uint64, diskGUID [16]byte, partitionCRC uint32) []byte {
	header := make([]byte, sectorSize)
	copy(header[:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], 92)
	binary.LittleEndian.PutUint64(header[24:32], current)
	binary.LittleEndian.PutUint64(header[32:40], backup)
	binary.LittleEndian.PutUint64(header[40:48], officialGPTFirstUsable)
	binary.LittleEndian.PutUint64(header[48:56], officialGPTLastUsable)
	copy(header[56:72], diskGUID[:])
	binary.LittleEndian.PutUint64(header[72:80], table)
	binary.LittleEndian.PutUint32(header[80:84], officialGPTEntries)
	binary.LittleEndian.PutUint32(header[84:88], officialGPTEntrySize)
	binary.LittleEndian.PutUint32(header[88:92], partitionCRC)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:92]))
	return header
}
