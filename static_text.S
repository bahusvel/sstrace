
static.text:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:	31 ed                	xor    %ebp,%ebp
   2:	49 89 d1             	mov    %rdx,%r9
   5:	5e                   	pop    %rsi
   6:	48 89 e2             	mov    %rsp,%rdx
   9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
   d:	50                   	push   %rax
   e:	54                   	push   %rsp
   f:	49 c7 c0 50 05 40 00 	mov    $0x400550,%r8
  16:	48 c7 c1 e0 04 40 00 	mov    $0x4004e0,%rcx
  1d:	48 c7 c7 c2 04 40 00 	mov    $0x4004c2,%rdi
  24:	ff 15 16 0c 20 00    	callq  *0x200c16(%rip)        # 0x200c40
  2a:	f4                   	hlt    
  2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  30:	b8 2f 10 60 00       	mov    $0x60102f,%eax
  35:	55                   	push   %rbp
  36:	48 2d 28 10 60 00    	sub    $0x601028,%rax
  3c:	48 83 f8 0e          	cmp    $0xe,%rax
  40:	48 89 e5             	mov    %rsp,%rbp
  43:	76 1b                	jbe    0x60
  45:	b8 00 00 00 00       	mov    $0x0,%eax
  4a:	48 85 c0             	test   %rax,%rax
  4d:	74 11                	je     0x60
  4f:	5d                   	pop    %rbp
  50:	bf 28 10 60 00       	mov    $0x601028,%edi
  55:	ff e0                	jmpq   *%rax
  57:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  5e:	00 00 
  60:	5d                   	pop    %rbp
  61:	c3                   	retq   
  62:	0f 1f 40 00          	nopl   0x0(%rax)
  66:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  6d:	00 00 00 
  70:	be 28 10 60 00       	mov    $0x601028,%esi
  75:	55                   	push   %rbp
  76:	48 81 ee 28 10 60 00 	sub    $0x601028,%rsi
  7d:	48 c1 fe 03          	sar    $0x3,%rsi
  81:	48 89 e5             	mov    %rsp,%rbp
  84:	48 89 f0             	mov    %rsi,%rax
  87:	48 c1 e8 3f          	shr    $0x3f,%rax
  8b:	48 01 c6             	add    %rax,%rsi
  8e:	48 d1 fe             	sar    %rsi
  91:	74 15                	je     0xa8
  93:	b8 00 00 00 00       	mov    $0x0,%eax
  98:	48 85 c0             	test   %rax,%rax
  9b:	74 0b                	je     0xa8
  9d:	5d                   	pop    %rbp
  9e:	bf 28 10 60 00       	mov    $0x601028,%edi
  a3:	ff e0                	jmpq   *%rax
  a5:	0f 1f 00             	nopl   (%rax)
  a8:	5d                   	pop    %rbp
  a9:	c3                   	retq   
  aa:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  b0:	80 3d c1 0b 20 00 00 	cmpb   $0x0,0x200bc1(%rip)        # 0x200c78
  b7:	75 11                	jne    0xca
  b9:	55                   	push   %rbp
  ba:	48 89 e5             	mov    %rsp,%rbp
  bd:	e8 6e ff ff ff       	callq  0x30
  c2:	5d                   	pop    %rbp
  c3:	c6 05 ae 0b 20 00 01 	movb   $0x1,0x200bae(%rip)        # 0x200c78
  ca:	f3 c3                	repz retq 
  cc:	0f 1f 40 00          	nopl   0x0(%rax)
  d0:	bf 58 0e 60 00       	mov    $0x600e58,%edi
  d5:	48 83 3f 00          	cmpq   $0x0,(%rdi)
  d9:	75 05                	jne    0xe0
  db:	eb 93                	jmp    0x70
  dd:	0f 1f 00             	nopl   (%rax)
  e0:	b8 00 00 00 00       	mov    $0x0,%eax
  e5:	48 85 c0             	test   %rax,%rax
  e8:	74 f1                	je     0xdb
  ea:	55                   	push   %rbp
  eb:	48 89 e5             	mov    %rsp,%rbp
  ee:	ff d0                	callq  *%rax
  f0:	5d                   	pop    %rbp
  f1:	e9 7a ff ff ff       	jmpq   0x70
  f6:	55                   	push   %rbp
  f7:	48 89 e5             	mov    %rsp,%rbp
  fa:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  fe:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
 102:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
 106:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
 10a:	48 89 d7             	mov    %rdx,%rdi
 10d:	0f 05                	syscall 
 10f:	90                   	nop
 110:	5d                   	pop    %rbp
 111:	c3                   	retq   
 112:	55                   	push   %rbp
 113:	48 89 e5             	mov    %rsp,%rbp
 116:	be 0a 00 00 00       	mov    $0xa,%esi
 11b:	bf 3c 00 00 00       	mov    $0x3c,%edi
 120:	e8 d1 ff ff ff       	callq  0xf6
 125:	90                   	nop
 126:	5d                   	pop    %rbp
 127:	c3                   	retq   
 128:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
 12f:	00 
 130:	41 57                	push   %r15
 132:	41 56                	push   %r14
 134:	41 89 ff             	mov    %edi,%r15d
 137:	41 55                	push   %r13
 139:	41 54                	push   %r12
 13b:	4c 8d 25 56 09 20 00 	lea    0x200956(%rip),%r12        # 0x200a98
 142:	55                   	push   %rbp
 143:	48 8d 2d 56 09 20 00 	lea    0x200956(%rip),%rbp        # 0x200aa0
 14a:	53                   	push   %rbx
 14b:	49 89 f6             	mov    %rsi,%r14
 14e:	49 89 d5             	mov    %rdx,%r13
 151:	4c 29 e5             	sub    %r12,%rbp
 154:	48 83 ec 08          	sub    $0x8,%rsp
 158:	48 c1 fd 03          	sar    $0x3,%rbp
 15c:	e8 7f fe ff ff       	callq  0xffffffffffffffe0
 161:	48 85 ed             	test   %rbp,%rbp
 164:	74 20                	je     0x186
 166:	31 db                	xor    %ebx,%ebx
 168:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
 16f:	00 
 170:	4c 89 ea             	mov    %r13,%rdx
 173:	4c 89 f6             	mov    %r14,%rsi
 176:	44 89 ff             	mov    %r15d,%edi
 179:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
 17d:	48 83 c3 01          	add    $0x1,%rbx
 181:	48 39 dd             	cmp    %rbx,%rbp
 184:	75 ea                	jne    0x170
 186:	48 83 c4 08          	add    $0x8,%rsp
 18a:	5b                   	pop    %rbx
 18b:	5d                   	pop    %rbp
 18c:	41 5c                	pop    %r12
 18e:	41 5d                	pop    %r13
 190:	41 5e                	pop    %r14
 192:	41 5f                	pop    %r15
 194:	c3                   	retq   
 195:	90                   	nop
 196:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 19d:	00 00 00 
 1a0:	f3 c3                	repz retq 
