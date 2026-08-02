package mikrotik

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	fat16BytesPerSector    = 512
	fat16SectorsPerCluster = 4
	fat16ReservedSectors   = 4
	fat16Copies            = 2
	fat16RootEntries       = 512
	fat16SectorsPerFAT     = 64
	fat16RootSectors       = 32
	fat16DataStartSector   = fat16ReservedSectors + fat16Copies*fat16SectorsPerFAT + fat16RootSectors
	fat16ClusterBytes      = fat16BytesPerSector * fat16SectorsPerCluster
	maxEFILoaderBytes      = 16 * 1024 * 1024
	maxEFIMapBytes         = 1024 * 1024
)

var (
	fatNameVolume  = [11]byte{'R', 'O', 'S', 'B', 'O', 'O', 'T', ' ', ' ', ' ', ' '}
	fatNameEFI     = [11]byte{'E', 'F', 'I', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
	fatNameBoot    = [11]byte{'B', 'O', 'O', 'T', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
	fatNameLoader  = [11]byte{'B', 'O', 'O', 'T', 'X', '6', '4', ' ', 'E', 'F', 'I'}
	fatNameMap     = [11]byte{'M', 'A', 'P', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
	fatNameCurrent = [11]byte{'.', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
	fatNameParent  = [11]byte{'.', '.', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
)

type fat16Allocation struct {
	startCluster uint16
}

type fat16DirectoryEntry struct {
	attributes byte
	cluster    uint16
	size       uint32
}

type fat16View struct {
	image            []byte
	fat              []byte
	root             []byte
	dataOffset       int
	clusterBytes     int
	dataClusterCount uint16
}

func buildUEFIFAT16(startSector, sectors uint32, loader, mapData []byte) ([]byte, error) {
	if startSector != officialBootStartSector || sectors != officialBootSectors {
		return nil, fmt.Errorf("FAT16 ESP geometry does not match the validated RouterOS boot partition")
	}
	if err := validateEFILoader(loader); err != nil {
		return nil, err
	}
	if len(mapData) == 0 || len(mapData) > maxEFIMapBytes || len(mapData)%4 != 0 {
		return nil, fmt.Errorf("RouterOS boot map has an invalid size of %d bytes", len(mapData))
	}
	imageBytes := uint64(sectors) * fat16BytesPerSector
	if imageBytes > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("FAT16 ESP is too large for this platform")
	}
	image := make([]byte, int(imageBytes))
	dataSectors := int(sectors) - fat16DataStartSector
	if dataSectors <= 0 || dataSectors%fat16SectorsPerCluster != 0 {
		return nil, fmt.Errorf("FAT16 ESP has invalid data geometry")
	}
	clusterCount := dataSectors / fat16SectorsPerCluster
	if clusterCount < 4085 || clusterCount >= 65525 {
		return nil, fmt.Errorf("FAT16 ESP cluster count %d is outside the FAT16 range", clusterCount)
	}
	fatEntries := fat16SectorsPerFAT * fat16BytesPerSector / 2
	if clusterCount+2 > fatEntries {
		return nil, fmt.Errorf("FAT16 table cannot describe all data clusters")
	}
	fat := make([]uint16, fatEntries)
	fat[0], fat[1] = 0xfff8, 0xffff
	nextCluster := uint16(2)
	allocate := func(data []byte) (fat16Allocation, error) {
		clusters := (len(data) + fat16ClusterBytes - 1) / fat16ClusterBytes
		if clusters == 0 {
			return fat16Allocation{}, fmt.Errorf("cannot allocate an empty FAT16 object")
		}
		if int(nextCluster)+clusters > clusterCount+2 {
			return fat16Allocation{}, fmt.Errorf("UEFI boot files do not fit in the FAT16 ESP")
		}
		allocation := fat16Allocation{startCluster: nextCluster}
		for index := 0; index < clusters; index++ {
			cluster := nextCluster + uint16(index)
			if index == clusters-1 {
				fat[cluster] = 0xffff
			} else {
				fat[cluster] = cluster + 1
			}
			start := index * fat16ClusterBytes
			end := start + fat16ClusterBytes
			if end > len(data) {
				end = len(data)
			}
			clusterOffset := fat16DataStartSector*fat16BytesPerSector + int(cluster-2)*fat16ClusterBytes
			copy(image[clusterOffset:clusterOffset+(end-start)], data[start:end])
		}
		nextCluster += uint16(clusters)
		return allocation, nil
	}

	efiDirectory, err := allocate(make([]byte, fat16ClusterBytes))
	if err != nil {
		return nil, err
	}
	bootDirectory, err := allocate(make([]byte, fat16ClusterBytes))
	if err != nil {
		return nil, err
	}
	loaderAllocation, err := allocate(loader)
	if err != nil {
		return nil, err
	}
	mapAllocation, err := allocate(mapData)
	if err != nil {
		return nil, err
	}

	writeFAT16BootSector(image[:fat16BytesPerSector], startSector, sectors, loader, mapData)
	rootOffset := (fat16ReservedSectors + fat16Copies*fat16SectorsPerFAT) * fat16BytesPerSector
	root := image[rootOffset : rootOffset+fat16RootSectors*fat16BytesPerSector]
	writeFAT16DirectoryEntry(root[0:32], fatNameVolume, 0x08, 0, 0)
	writeFAT16DirectoryEntry(root[32:64], fatNameEFI, 0x10, efiDirectory.startCluster, 0)
	writeFAT16DirectoryEntry(root[64:96], fatNameMap, 0x20, mapAllocation.startCluster, uint32(len(mapData)))

	efiDirectoryBytes := fat16ClusterSlice(image, efiDirectory.startCluster)
	writeFAT16DirectoryEntry(efiDirectoryBytes[0:32], fatNameCurrent, 0x10, efiDirectory.startCluster, 0)
	writeFAT16DirectoryEntry(efiDirectoryBytes[32:64], fatNameParent, 0x10, 0, 0)
	writeFAT16DirectoryEntry(efiDirectoryBytes[64:96], fatNameBoot, 0x10, bootDirectory.startCluster, 0)

	bootDirectoryBytes := fat16ClusterSlice(image, bootDirectory.startCluster)
	writeFAT16DirectoryEntry(bootDirectoryBytes[0:32], fatNameCurrent, 0x10, bootDirectory.startCluster, 0)
	writeFAT16DirectoryEntry(bootDirectoryBytes[32:64], fatNameParent, 0x10, efiDirectory.startCluster, 0)
	writeFAT16DirectoryEntry(bootDirectoryBytes[64:96], fatNameLoader, 0x20, loaderAllocation.startCluster, uint32(len(loader)))

	serializedFAT := make([]byte, fat16SectorsPerFAT*fat16BytesPerSector)
	for index, value := range fat {
		binary.LittleEndian.PutUint16(serializedFAT[index*2:index*2+2], value)
	}
	firstFATOffset := fat16ReservedSectors * fat16BytesPerSector
	copy(image[firstFATOffset:firstFATOffset+len(serializedFAT)], serializedFAT)
	copy(image[firstFATOffset+len(serializedFAT):firstFATOffset+2*len(serializedFAT)], serializedFAT)
	if err := validateUEFIFAT16(image, startSector, sectors, loader, mapData); err != nil {
		return nil, fmt.Errorf("validate generated FAT16 ESP: %w", err)
	}
	return image, nil
}

func writeFAT16BootSector(sector []byte, startSector, sectors uint32, loader, mapData []byte) {
	copy(sector[0:3], []byte{0xeb, 0x3c, 0x90})
	copy(sector[3:11], []byte("CHRINST "))
	binary.LittleEndian.PutUint16(sector[11:13], fat16BytesPerSector)
	sector[13] = fat16SectorsPerCluster
	binary.LittleEndian.PutUint16(sector[14:16], fat16ReservedSectors)
	sector[16] = fat16Copies
	binary.LittleEndian.PutUint16(sector[17:19], fat16RootEntries)
	binary.LittleEndian.PutUint16(sector[19:21], 0)
	sector[21] = 0xf8
	binary.LittleEndian.PutUint16(sector[22:24], fat16SectorsPerFAT)
	binary.LittleEndian.PutUint16(sector[24:26], 32)
	binary.LittleEndian.PutUint16(sector[26:28], 4)
	binary.LittleEndian.PutUint32(sector[28:32], startSector)
	binary.LittleEndian.PutUint32(sector[32:36], sectors)
	sector[36] = 0x80
	sector[38] = 0x29
	identifierInput := make([]byte, 0, len(loader)+len(mapData))
	identifierInput = append(identifierInput, loader...)
	identifierInput = append(identifierInput, mapData...)
	identifier := sha256.Sum256(identifierInput)
	binary.LittleEndian.PutUint32(sector[39:43], binary.LittleEndian.Uint32(identifier[:4]))
	copy(sector[43:54], fatNameVolume[:])
	copy(sector[54:62], []byte("FAT16   "))
	sector[510], sector[511] = 0x55, 0xaa
}

func writeFAT16DirectoryEntry(entry []byte, name [11]byte, attributes byte, cluster uint16, size uint32) {
	copy(entry[:11], name[:])
	entry[11] = attributes
	// A fixed timestamp keeps prepared images reproducible.
	date := uint16((2026-1980)<<9 | 1<<5 | 1)
	binary.LittleEndian.PutUint16(entry[16:18], date)
	binary.LittleEndian.PutUint16(entry[18:20], date)
	binary.LittleEndian.PutUint16(entry[24:26], date)
	binary.LittleEndian.PutUint16(entry[26:28], cluster)
	binary.LittleEndian.PutUint32(entry[28:32], size)
}

func fat16ClusterSlice(image []byte, cluster uint16) []byte {
	offset := fat16DataStartSector*fat16BytesPerSector + int(cluster-2)*fat16ClusterBytes
	return image[offset : offset+fat16ClusterBytes]
}

func validateEFILoader(loader []byte) error {
	if len(loader) < 0x88 || len(loader) > maxEFILoaderBytes || loader[0] != 'M' || loader[1] != 'Z' {
		return fmt.Errorf("RouterOS BOOTX64.EFI is not a bounded x86 EFI image")
	}
	peOffset := binary.LittleEndian.Uint32(loader[0x3c:0x40])
	if uint64(peOffset)+6 > uint64(len(loader)) || string(loader[peOffset:peOffset+4]) != "PE\x00\x00" || binary.LittleEndian.Uint16(loader[peOffset+4:peOffset+6]) != 0x8664 {
		return fmt.Errorf("RouterOS BOOTX64.EFI does not contain an x86-64 PE header")
	}
	return nil
}

func validateUEFIFAT16(image []byte, startSector, sectors uint32, loader, mapData []byte) error {
	view, err := parseFAT16(image, startSector, sectors)
	if err != nil {
		return err
	}
	efi, err := findFAT16DirectoryEntry(view.root, fatNameEFI)
	if err != nil || efi.attributes&0x10 == 0 {
		return fmt.Errorf("generated FAT16 ESP is missing the EFI directory")
	}
	efiDirectory, err := view.readChain(efi.cluster)
	if err != nil {
		return err
	}
	boot, err := findFAT16DirectoryEntry(efiDirectory, fatNameBoot)
	if err != nil || boot.attributes&0x10 == 0 {
		return fmt.Errorf("generated FAT16 ESP is missing the EFI/BOOT directory")
	}
	bootDirectory, err := view.readChain(boot.cluster)
	if err != nil {
		return err
	}
	loaderEntry, err := findFAT16DirectoryEntry(bootDirectory, fatNameLoader)
	if err != nil || loaderEntry.attributes&0x10 != 0 {
		return fmt.Errorf("generated FAT16 ESP is missing BOOTX64.EFI")
	}
	loaderValue, err := view.readFile(loaderEntry)
	if err != nil {
		return err
	}
	if !bytes.Equal(loaderValue, loader) {
		return fmt.Errorf("generated FAT16 BOOTX64.EFI differs from the verified source")
	}
	mapEntry, err := findFAT16DirectoryEntry(view.root, fatNameMap)
	if err != nil || mapEntry.attributes&0x10 != 0 {
		return fmt.Errorf("generated FAT16 ESP is missing the RouterOS boot map")
	}
	mapValue, err := view.readFile(mapEntry)
	if err != nil {
		return err
	}
	if !bytes.Equal(mapValue, mapData) {
		return fmt.Errorf("generated FAT16 boot map differs from the verified source")
	}
	return nil
}

func parseFAT16(image []byte, startSector, sectors uint32) (fat16View, error) {
	if uint64(len(image)) != uint64(sectors)*fat16BytesPerSector || len(image) < fat16BytesPerSector {
		return fat16View{}, fmt.Errorf("FAT16 ESP size is invalid")
	}
	boot := image[:fat16BytesPerSector]
	if boot[510] != 0x55 || boot[511] != 0xaa || binary.LittleEndian.Uint16(boot[11:13]) != fat16BytesPerSector || boot[13] != fat16SectorsPerCluster || binary.LittleEndian.Uint16(boot[14:16]) != fat16ReservedSectors || boot[16] != fat16Copies || binary.LittleEndian.Uint16(boot[17:19]) != fat16RootEntries || binary.LittleEndian.Uint16(boot[22:24]) != fat16SectorsPerFAT || binary.LittleEndian.Uint32(boot[28:32]) != startSector || binary.LittleEndian.Uint32(boot[32:36]) != sectors || string(boot[54:62]) != "FAT16   " {
		return fat16View{}, fmt.Errorf("FAT16 ESP boot parameters are invalid")
	}
	firstFATOffset := fat16ReservedSectors * fat16BytesPerSector
	fatBytes := fat16SectorsPerFAT * fat16BytesPerSector
	firstFAT := image[firstFATOffset : firstFATOffset+fatBytes]
	secondFAT := image[firstFATOffset+fatBytes : firstFATOffset+2*fatBytes]
	if !bytes.Equal(firstFAT, secondFAT) || binary.LittleEndian.Uint16(firstFAT[:2]) != 0xfff8 || binary.LittleEndian.Uint16(firstFAT[2:4]) != 0xffff {
		return fat16View{}, fmt.Errorf("FAT16 allocation tables are invalid or inconsistent")
	}
	rootOffset := (fat16ReservedSectors + fat16Copies*fat16SectorsPerFAT) * fat16BytesPerSector
	rootBytes := fat16RootSectors * fat16BytesPerSector
	dataSectors := int(sectors) - fat16DataStartSector
	clusterCount := dataSectors / fat16SectorsPerCluster
	return fat16View{
		image:            image,
		fat:              firstFAT,
		root:             image[rootOffset : rootOffset+rootBytes],
		dataOffset:       fat16DataStartSector * fat16BytesPerSector,
		clusterBytes:     fat16ClusterBytes,
		dataClusterCount: uint16(clusterCount),
	}, nil
}

func findFAT16DirectoryEntry(directory []byte, expected [11]byte) (fat16DirectoryEntry, error) {
	for offset := 0; offset+32 <= len(directory); offset += 32 {
		entry := directory[offset : offset+32]
		if entry[0] == 0x00 {
			break
		}
		if entry[0] == 0xe5 || entry[11] == 0x0f || entry[11]&0x08 != 0 {
			continue
		}
		if bytes.Equal(entry[:11], expected[:]) {
			return fat16DirectoryEntry{
				attributes: entry[11],
				cluster:    binary.LittleEndian.Uint16(entry[26:28]),
				size:       binary.LittleEndian.Uint32(entry[28:32]),
			}, nil
		}
	}
	return fat16DirectoryEntry{}, fmt.Errorf("FAT16 directory entry %q was not found", string(expected[:]))
}

func (view fat16View) readChain(start uint16) ([]byte, error) {
	if start < 2 || int(start-2) >= int(view.dataClusterCount) {
		return nil, fmt.Errorf("FAT16 chain starts at invalid cluster %d", start)
	}
	seen := make(map[uint16]struct{})
	value := make([]byte, 0, view.clusterBytes)
	cluster := start
	for {
		if cluster < 2 || int(cluster-2) >= int(view.dataClusterCount) {
			return nil, fmt.Errorf("FAT16 chain references invalid cluster %d", cluster)
		}
		if _, exists := seen[cluster]; exists {
			return nil, fmt.Errorf("FAT16 chain contains a loop at cluster %d", cluster)
		}
		seen[cluster] = struct{}{}
		offset := view.dataOffset + int(cluster-2)*view.clusterBytes
		value = append(value, view.image[offset:offset+view.clusterBytes]...)
		fatOffset := int(cluster) * 2
		if fatOffset+2 > len(view.fat) {
			return nil, fmt.Errorf("FAT16 entry for cluster %d is outside the allocation table", cluster)
		}
		next := binary.LittleEndian.Uint16(view.fat[fatOffset : fatOffset+2])
		if next >= 0xfff8 {
			return value, nil
		}
		if next < 2 || next == 0xfff7 {
			return nil, fmt.Errorf("FAT16 chain contains invalid next cluster %04x", next)
		}
		cluster = next
	}
}

func (view fat16View) readFile(entry fat16DirectoryEntry) ([]byte, error) {
	if entry.size == 0 {
		if entry.cluster != 0 {
			return nil, fmt.Errorf("empty FAT16 file has a non-zero cluster")
		}
		return nil, nil
	}
	value, err := view.readChain(entry.cluster)
	if err != nil {
		return nil, err
	}
	if uint64(entry.size) > uint64(len(value)) {
		return nil, fmt.Errorf("FAT16 file size exceeds its cluster chain")
	}
	return value[:entry.size], nil
}
