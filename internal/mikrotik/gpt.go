package mikrotik

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"unicode/utf16"
)

const (
	officialCHRImageSectors   = 262144
	officialGPTEntries        = 128
	officialGPTEntrySize      = 128
	officialGPTTableSectors   = 32
	officialGPTPrimaryTable   = 2
	officialGPTBackupTable    = 258048
	officialGPTBackupHeader   = 262143
	officialGPTFirstUsable    = 34
	officialGPTLastUsable     = 258047
	officialBootStartSector   = 34
	officialBootSectors       = 65536
	officialSystemStartSector = 65570
	officialSystemSectors     = 192478
)

var (
	// GPT GUIDs use little-endian encoding for their first three fields.
	efiSystemPartitionGUID = [16]byte{0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}
	linuxFilesystemGUID    = [16]byte{0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}
)

type gptMetadata struct {
	currentLBA      uint64
	backupLBA       uint64
	firstUsableLBA  uint64
	lastUsableLBA   uint64
	diskGUID        [16]byte
	entryLBA        uint64
	entryCount      uint32
	entrySize       uint32
	partitionTable  []byte
	partitionCRC32  uint32
	headerCRC32     uint32
	headerSizeBytes uint32
}

type gptPartition struct {
	typeGUID   [16]byte
	uniqueGUID [16]byte
	firstLBA   uint64
	lastLBA    uint64
	attributes uint64
	name       string
}

func validateOfficialUEFIGPT(path string, layout Layout) (Partition, error) {
	bootPartition, systemPartition, err := validateOfficialMBRLayout(layout)
	if err != nil {
		return Partition{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return Partition{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Partition{}, err
	}
	expectedBytes := int64(officialCHRImageSectors * sectorSize)
	if info.Size() != expectedBytes {
		return Partition{}, fmt.Errorf("UEFI preparation requires the validated %d-byte CHR image, found %d bytes", expectedBytes, info.Size())
	}
	primary, err := readGPTMetadata(file, 1, officialCHRImageSectors)
	if err != nil {
		return Partition{}, fmt.Errorf("validate primary GPT: %w", err)
	}
	backup, err := readGPTMetadata(file, primary.backupLBA, officialCHRImageSectors)
	if err != nil {
		return Partition{}, fmt.Errorf("validate backup GPT: %w", err)
	}
	if err := validateOfficialGPTHeaders(primary, backup); err != nil {
		return Partition{}, err
	}
	if !bytes.Equal(primary.partitionTable, backup.partitionTable) {
		return Partition{}, fmt.Errorf("primary and backup GPT partition tables differ")
	}
	first, err := parseGPTPartition(primary.partitionTable[:officialGPTEntrySize])
	if err != nil {
		return Partition{}, fmt.Errorf("parse RouterOS boot GPT entry: %w", err)
	}
	second, err := parseGPTPartition(primary.partitionTable[officialGPTEntrySize : 2*officialGPTEntrySize])
	if err != nil {
		return Partition{}, fmt.Errorf("parse RouterOS system GPT entry: %w", err)
	}
	if first.typeGUID != efiSystemPartitionGUID || first.firstLBA != officialBootStartSector || first.lastLBA != officialBootStartSector+officialBootSectors-1 || first.attributes != 4 || first.name != "RouterOS Boot" {
		return Partition{}, fmt.Errorf("RouterOS boot GPT entry does not match the validated UEFI source layout")
	}
	if second.typeGUID != linuxFilesystemGUID || second.firstLBA != officialSystemStartSector || second.lastLBA != officialSystemStartSector+officialSystemSectors-1 || second.attributes != 0 || second.name != "RouterOS" {
		return Partition{}, fmt.Errorf("RouterOS system GPT entry does not match the validated UEFI source layout")
	}
	if zeroGUID(first.uniqueGUID) || zeroGUID(second.uniqueGUID) || first.uniqueGUID == second.uniqueGUID {
		return Partition{}, fmt.Errorf("RouterOS GPT partition identities are missing or duplicated")
	}
	for offset := 2 * officialGPTEntrySize; offset < len(primary.partitionTable); offset += officialGPTEntrySize {
		if !allZero(primary.partitionTable[offset : offset+officialGPTEntrySize]) {
			return Partition{}, fmt.Errorf("unexpected GPT partition entry %d", offset/officialGPTEntrySize+1)
		}
	}
	if uint64(bootPartition.StartSector) != first.firstLBA || uint64(bootPartition.StartSector+bootPartition.Sectors-1) != first.lastLBA || uint64(systemPartition.StartSector) != second.firstLBA || uint64(systemPartition.StartSector+systemPartition.Sectors-1) != second.lastLBA {
		return Partition{}, fmt.Errorf("hybrid MBR and GPT partition geometry differ")
	}
	return bootPartition, nil
}

func validateOfficialMBRLayout(layout Layout) (Partition, Partition, error) {
	if len(layout.Partitions) != 2 {
		return Partition{}, Partition{}, fmt.Errorf("UEFI preparation requires exactly two validated MBR partitions")
	}
	byIndex := make(map[int]Partition, len(layout.Partitions))
	for _, partition := range layout.Partitions {
		byIndex[partition.Index] = partition
	}
	boot, bootOK := byIndex[1]
	system, systemOK := byIndex[2]
	if !bootOK || !systemOK {
		return Partition{}, Partition{}, fmt.Errorf("UEFI preparation requires MBR partitions 1 and 2")
	}
	if boot.Type != 0x83 || !boot.Bootable || boot.StartSector != officialBootStartSector || boot.Sectors != officialBootSectors {
		return Partition{}, Partition{}, fmt.Errorf("RouterOS boot MBR entry does not match the validated UEFI source layout")
	}
	if system.Type != 0x83 || system.Bootable || system.StartSector != officialSystemStartSector || system.Sectors != officialSystemSectors {
		return Partition{}, Partition{}, fmt.Errorf("RouterOS system MBR entry does not match the validated UEFI source layout")
	}
	return boot, system, nil
}

func readGPTMetadata(file *os.File, lba, diskSectors uint64) (gptMetadata, error) {
	if lba >= diskSectors {
		return gptMetadata{}, fmt.Errorf("header LBA %d is outside the image", lba)
	}
	sector := make([]byte, sectorSize)
	if _, err := file.ReadAt(sector, int64(lba*sectorSize)); err != nil {
		return gptMetadata{}, err
	}
	if string(sector[:8]) != "EFI PART" {
		return gptMetadata{}, fmt.Errorf("missing GPT signature at LBA %d", lba)
	}
	headerSize := binary.LittleEndian.Uint32(sector[12:16])
	if headerSize < 92 || headerSize > sectorSize {
		return gptMetadata{}, fmt.Errorf("invalid GPT header size %d", headerSize)
	}
	storedHeaderCRC := binary.LittleEndian.Uint32(sector[16:20])
	header := append([]byte(nil), sector[:headerSize]...)
	for index := 16; index < 20; index++ {
		header[index] = 0
	}
	if calculated := crc32.ChecksumIEEE(header); calculated != storedHeaderCRC {
		return gptMetadata{}, fmt.Errorf("GPT header CRC mismatch: stored %08x calculated %08x", storedHeaderCRC, calculated)
	}
	if revision := binary.LittleEndian.Uint32(sector[8:12]); revision != 0x00010000 {
		return gptMetadata{}, fmt.Errorf("unsupported GPT revision %08x", revision)
	}
	if binary.LittleEndian.Uint32(sector[20:24]) != 0 {
		return gptMetadata{}, fmt.Errorf("GPT reserved header field is non-zero")
	}
	metadata := gptMetadata{
		currentLBA:      binary.LittleEndian.Uint64(sector[24:32]),
		backupLBA:       binary.LittleEndian.Uint64(sector[32:40]),
		firstUsableLBA:  binary.LittleEndian.Uint64(sector[40:48]),
		lastUsableLBA:   binary.LittleEndian.Uint64(sector[48:56]),
		entryLBA:        binary.LittleEndian.Uint64(sector[72:80]),
		entryCount:      binary.LittleEndian.Uint32(sector[80:84]),
		entrySize:       binary.LittleEndian.Uint32(sector[84:88]),
		partitionCRC32:  binary.LittleEndian.Uint32(sector[88:92]),
		headerCRC32:     storedHeaderCRC,
		headerSizeBytes: headerSize,
	}
	copy(metadata.diskGUID[:], sector[56:72])
	if metadata.currentLBA != lba || metadata.backupLBA >= diskSectors || metadata.firstUsableLBA > metadata.lastUsableLBA || metadata.lastUsableLBA >= diskSectors {
		return gptMetadata{}, fmt.Errorf("invalid GPT header geometry")
	}
	if metadata.entryCount == 0 || metadata.entryCount > 4096 || metadata.entrySize < 128 || metadata.entrySize > 4096 || metadata.entrySize%8 != 0 {
		return gptMetadata{}, fmt.Errorf("invalid GPT partition table dimensions")
	}
	tableBytes := uint64(metadata.entryCount) * uint64(metadata.entrySize)
	if tableBytes > 16*1024*1024 || metadata.entryLBA >= diskSectors || tableBytes > (diskSectors-metadata.entryLBA)*sectorSize {
		return gptMetadata{}, fmt.Errorf("GPT partition table is outside the image")
	}
	metadata.partitionTable = make([]byte, tableBytes)
	read, err := file.ReadAt(metadata.partitionTable, int64(metadata.entryLBA*sectorSize))
	if err != nil || read != len(metadata.partitionTable) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return gptMetadata{}, err
	}
	if calculated := crc32.ChecksumIEEE(metadata.partitionTable); calculated != metadata.partitionCRC32 {
		return gptMetadata{}, fmt.Errorf("GPT partition table CRC mismatch: stored %08x calculated %08x", metadata.partitionCRC32, calculated)
	}
	return metadata, nil
}

func validateOfficialGPTHeaders(primary, backup gptMetadata) error {
	if primary.currentLBA != 1 || primary.backupLBA != officialGPTBackupHeader || primary.firstUsableLBA != officialGPTFirstUsable || primary.lastUsableLBA != officialGPTLastUsable || primary.entryLBA != officialGPTPrimaryTable || primary.entryCount != officialGPTEntries || primary.entrySize != officialGPTEntrySize {
		return fmt.Errorf("primary GPT does not match the validated CHR geometry")
	}
	if uint64(primary.entryCount)*uint64(primary.entrySize) != officialGPTTableSectors*sectorSize {
		return fmt.Errorf("primary GPT partition table has an unexpected size")
	}
	if backup.currentLBA != officialGPTBackupHeader || backup.backupLBA != 1 || backup.firstUsableLBA != primary.firstUsableLBA || backup.lastUsableLBA != primary.lastUsableLBA || backup.entryLBA != officialGPTBackupTable || backup.entryCount != primary.entryCount || backup.entrySize != primary.entrySize {
		return fmt.Errorf("backup GPT does not match the validated CHR geometry")
	}
	if primary.diskGUID != backup.diskGUID || zeroGUID(primary.diskGUID) || primary.partitionCRC32 != backup.partitionCRC32 {
		return fmt.Errorf("primary and backup GPT identities differ")
	}
	return nil
}

func parseGPTPartition(entry []byte) (gptPartition, error) {
	if len(entry) != officialGPTEntrySize {
		return gptPartition{}, fmt.Errorf("invalid GPT entry size %d", len(entry))
	}
	var partition gptPartition
	copy(partition.typeGUID[:], entry[:16])
	copy(partition.uniqueGUID[:], entry[16:32])
	partition.firstLBA = binary.LittleEndian.Uint64(entry[32:40])
	partition.lastLBA = binary.LittleEndian.Uint64(entry[40:48])
	partition.attributes = binary.LittleEndian.Uint64(entry[48:56])
	nameUnits := make([]uint16, 0, 36)
	for offset := 56; offset < 128; offset += 2 {
		value := binary.LittleEndian.Uint16(entry[offset : offset+2])
		if value == 0 {
			break
		}
		nameUnits = append(nameUnits, value)
	}
	partition.name = string(utf16.Decode(nameUnits))
	return partition, nil
}

func zeroGUID(value [16]byte) bool {
	return allZero(value[:])
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
