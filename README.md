# go-pinject
Process injection a few different ways using direct syscalls with Bananaphone. 

Changed some of the simpler process injection methods in Ne0nD0g's go-shellcode repo to using direct syscalls.

In all the examples, the shellcode spawns calc.exe.

# Resources 

Bananaphone - https://github.com/C-Sto/BananaPhone/

go-shellcode - https://github.com/Ne0nd0g/go-shellcode

## Issues

I'm happy to fix issues and implement any changes that people submit. Known issues/improvments are listed below. 

EarlyBirdAPC - NtCreateUserProcess not implemented and is WIP (using CreateProcess instead). 
