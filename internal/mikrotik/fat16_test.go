package mikrotik

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestBuildUEFIFAT16PreservesVerifiedBootFiles(t *testing.T) {
	loader := testEFILoader(3*1024*1024 + 137)
	mapData := make([]byte, 60*1024)
	for index := range mapData {
		mapData[index] = byte(index * 17)
	}
	image, err := buildUEFIFAT16(officialBootStartSector, officialBootSectors, loader, mapData)
	if err != nil {
		t.Fatal(err)
	}
	if len(image) != officialBootSectors*sectorSize {
		t.Fatalf("FAT16 image size = %d", len(image))
	}
	if hidden := binary.LittleEndian.Uint32(image[28:32]); hidden != officialBootStartSector {
		t.Fatalf("hidden sectors = %d", hidden)
	}
	if err := validateUEFIFAT16(image, officialBootStartSector, officialBootSectors, loader, mapData); err != nil {
		t.Fatal(err)
	}
}

func TestValidateUEFIFAT16RejectsDivergentCopies(t *testing.T) {
	loader := testEFILoader(8192)
	mapData := make([]byte, 4096)
	image, err := buildUEFIFAT16(officialBootStartSector, officialBootSectors, loader, mapData)
	if err != nil {
		t.Fatal(err)
	}
	secondFATOffset := (fat16ReservedSectors + fat16SectorsPerFAT) * fat16BytesPerSector
	image[secondFATOffset+20] ^= 0xff
	if err := validateUEFIFAT16(image, officialBootStartSector, officialBootSectors, loader, mapData); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("expected divergent FAT rejection, got %v", err)
	}
}

func TestBuildUEFIFAT16RejectsNonEFIImage(t *testing.T) {
	if _, err := buildUEFIFAT16(officialBootStartSector, officialBootSectors, []byte("not EFI"), make([]byte, 4)); err == nil {
		t.Fatal("expected invalid EFI image to be rejected")
	}
}

func testEFILoader(size int) []byte {
	if size < 0x100 {
		size = 0x100
	}
	loader := make([]byte, size)
	loader[0], loader[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(loader[0x3c:0x40], 0x80)
	copy(loader[0x80:0x84], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(loader[0x84:0x86], 0x8664)
	for index := 0x100; index < len(loader); index++ {
		loader[index] = byte(index * 31)
	}
	return loader
}
