# go-pinject
Process injection a few different ways using direct syscalls with Bananaphone. 

Changed some of the simpler process injection methods in Ne0nD0g's go-shellcode repo to using direct syscalls.

# Resources 

Bananaphone - https://github.com/C-Sto/BananaPhone/

go-shellcode - https://github.com/Ne0nd0g/go-shellcode

Doge-Process-Injection - https://github.com/timwhitez/Doge-Process-Injection - A few syscalls needed an extra arg in the CreateRemoteThread code. Not sure if it's some sort of stack alignment issue. Found out about the added arg from this repo.

## Issues

I'm happy to fix issues and implement any changes that people submit. Known issues/improvments are listed below. Not sure if the fault lies with Bananaphone or my code. Probably the latter.

CreateRemoteThread - NtClose syscall panics (currently using CloseHandle instead)
EarlyBirdAPC - NtClose syscall panics (currently using CloseHandle instead), NtResumeThread panics more often than not but shellcode runs, NtCreateUserProcess not implemented (using CreateProcess instead)

