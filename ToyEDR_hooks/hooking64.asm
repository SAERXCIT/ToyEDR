.data

; Note: For 32 bit code prepend underscore
PUBLIC wSystemCall
wSystemCall	DWORD 0h

.code

CallSyscall proc
	mov r10, rcx
	mov eax, wSystemCall
	syscall
	ret
CallSyscall endp

end