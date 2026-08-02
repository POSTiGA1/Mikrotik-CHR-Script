package mikrotik

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
)

func prepareUEFIImage(ctx context.Context, runner command.Runner, imagePath string, layout Layout) error {
	bootPartition, err := validateOfficialUEFIGPT(imagePath, layout)
	if err != nil {
		return fmt.Errorf("validate official CHR UEFI source layout: %w", err)
	}
	loader, mapData, err := readUEFIBootFiles(ctx, runner, imagePath, bootPartition)
	if err != nil {
		return err
	}
	esp, err := buildUEFIFAT16(bootPartition.StartSector, bootPartition.Sectors, loader, mapData)
	if err != nil {
		return fmt.Errorf("build FAT16 UEFI system partition: %w", err)
	}
	file, err := os.OpenFile(imagePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	written, writeErr := file.WriteAt(esp, bootPartition.OffsetBytes)
	if writeErr == nil && written != len(esp) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write FAT16 UEFI system partition: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if _, err := validateOfficialUEFIGPT(imagePath, layout); err != nil {
		return fmt.Errorf("revalidate CHR partition tables after UEFI preparation: %w", err)
	}
	file, err = os.Open(imagePath)
	if err != nil {
		return err
	}
	readback := make([]byte, len(esp))
	read, readErr := file.ReadAt(readback, bootPartition.OffsetBytes)
	closeErr = file.Close()
	if readErr != nil || read != len(readback) {
		if readErr == nil {
			readErr = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("read back FAT16 UEFI system partition: %w", readErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := validateUEFIFAT16(readback, bootPartition.StartSector, bootPartition.Sectors, loader, mapData); err != nil {
		return fmt.Errorf("validate written FAT16 UEFI system partition: %w", err)
	}
	return nil
}

func readUEFIBootFiles(ctx context.Context, runner command.Runner, imagePath string, partition Partition) (loader, mapData []byte, returnErr error) {
	mountpoint, err := os.MkdirTemp("", "chr-install-uefi-")
	if err != nil {
		return nil, nil, err
	}
	mounted := false
	defer func() {
		if mounted {
			cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			if _, unmountErr := runner.Run(cleanupContext, "umount", mountpoint); unmountErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("unmount RouterOS boot partition: %w", unmountErr))
			}
			cancel()
		}
		if removeErr := os.Remove(mountpoint); removeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove RouterOS boot mountpoint: %w", removeErr))
		}
	}()
	options := fmt.Sprintf("loop,ro,nosuid,nodev,noexec,offset=%d,sizelimit=%d", partition.OffsetBytes, partition.SizeBytes)
	if _, err := runner.Run(ctx, "mount", "-o", options, imagePath, mountpoint); err != nil {
		return nil, nil, fmt.Errorf("mount verified RouterOS boot partition read-only: %w", err)
	}
	mounted = true
	efiDirectory := filepath.Join(mountpoint, "EFI")
	bootDirectory := filepath.Join(efiDirectory, "BOOT")
	for _, directory := range []string{efiDirectory, bootDirectory} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("verified RouterOS boot partition is missing a safe %s directory", filepath.Base(directory))
		}
	}
	loader, err = readBoundedRegularFile(filepath.Join(bootDirectory, "BOOTX64.EFI"), maxEFILoaderBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read RouterOS BOOTX64.EFI: %w", err)
	}
	if err := validateEFILoader(loader); err != nil {
		return nil, nil, err
	}
	mapData, err = readBoundedRegularFile(filepath.Join(mountpoint, "map"), maxEFIMapBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read RouterOS boot map: %w", err)
	}
	if len(mapData) == 0 || len(mapData)%4 != 0 {
		return nil, nil, fmt.Errorf("RouterOS boot map has an invalid size of %d bytes", len(mapData))
	}
	return loader, mapData, nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%s is not a bounded regular file", path)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(value)) != info.Size() {
		return nil, fmt.Errorf("%s changed while it was being read", path)
	}
	return value, nil
}
