
static:     file format elf64-x86-64


Disassembly of section .init:

0000000000400390 <_init>:
  400390:	48 83 ec 08          	sub    $0x8,%rsp
  400394:	48 8b 05 5d 0c 20 00 	mov    0x200c5d(%rip),%rax        # 600ff8 <_DYNAMIC+0x198>
  40039b:	48 85 c0             	test   %rax,%rax
  40039e:	74 02                	je     4003a2 <_init+0x12>
  4003a0:	ff d0                	callq  *%rax
  4003a2:	48 83 c4 08          	add    $0x8,%rsp
  4003a6:	c3                   	retq   

Disassembly of section .text:

00000000004003b0 <_start>:
  4003b0:	31 ed                	xor    %ebp,%ebp
  4003b2:	49 89 d1             	mov    %rdx,%r9
  4003b5:	5e                   	pop    %rsi
  4003b6:	48 89 e2             	mov    %rsp,%rdx
  4003b9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4003bd:	50                   	push   %rax
  4003be:	54                   	push   %rsp
  4003bf:	49 c7 c0 50 05 40 00 	mov    $0x400550,%r8
  4003c6:	48 c7 c1 e0 04 40 00 	mov    $0x4004e0,%rcx
  4003cd:	48 c7 c7 bf 04 40 00 	mov    $0x4004bf,%rdi
  4003d4:	ff 15 16 0c 20 00    	callq  *0x200c16(%rip)        # 600ff0 <_DYNAMIC+0x190>
  4003da:	f4                   	hlt    
  4003db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000004003e0 <deregister_tm_clones>:
  4003e0:	b8 2f 10 60 00       	mov    $0x60102f,%eax
  4003e5:	55                   	push   %rbp
  4003e6:	48 2d 28 10 60 00    	sub    $0x601028,%rax
  4003ec:	48 83 f8 0e          	cmp    $0xe,%rax
  4003f0:	48 89 e5             	mov    %rsp,%rbp
  4003f3:	76 1b                	jbe    400410 <deregister_tm_clones+0x30>
  4003f5:	b8 00 00 00 00       	mov    $0x0,%eax
  4003fa:	48 85 c0             	test   %rax,%rax
  4003fd:	74 11                	je     400410 <deregister_tm_clones+0x30>
  4003ff:	5d                   	pop    %rbp
  400400:	bf 28 10 60 00       	mov    $0x601028,%edi
  400405:	ff e0                	jmpq   *%rax
  400407:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  40040e:	00 00 
  400410:	5d                   	pop    %rbp
  400411:	c3                   	retq   
  400412:	0f 1f 40 00          	nopl   0x0(%rax)
  400416:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40041d:	00 00 00 

0000000000400420 <register_tm_clones>:
  400420:	be 28 10 60 00       	mov    $0x601028,%esi
  400425:	55                   	push   %rbp
  400426:	48 81 ee 28 10 60 00 	sub    $0x601028,%rsi
  40042d:	48 c1 fe 03          	sar    $0x3,%rsi
  400431:	48 89 e5             	mov    %rsp,%rbp
  400434:	48 89 f0             	mov    %rsi,%rax
  400437:	48 c1 e8 3f          	shr    $0x3f,%rax
  40043b:	48 01 c6             	add    %rax,%rsi
  40043e:	48 d1 fe             	sar    %rsi
  400441:	74 15                	je     400458 <register_tm_clones+0x38>
  400443:	b8 00 00 00 00       	mov    $0x0,%eax
  400448:	48 85 c0             	test   %rax,%rax
  40044b:	74 0b                	je     400458 <register_tm_clones+0x38>
  40044d:	5d                   	pop    %rbp
  40044e:	bf 28 10 60 00       	mov    $0x601028,%edi
  400453:	ff e0                	jmpq   *%rax
  400455:	0f 1f 00             	nopl   (%rax)
  400458:	5d                   	pop    %rbp
  400459:	c3                   	retq   
  40045a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400460 <__do_global_dtors_aux>:
  400460:	80 3d c1 0b 20 00 00 	cmpb   $0x0,0x200bc1(%rip)        # 601028 <__TMC_END__>
  400467:	75 11                	jne    40047a <__do_global_dtors_aux+0x1a>
  400469:	55                   	push   %rbp
  40046a:	48 89 e5             	mov    %rsp,%rbp
  40046d:	e8 6e ff ff ff       	callq  4003e0 <deregister_tm_clones>
  400472:	5d                   	pop    %rbp
  400473:	c6 05 ae 0b 20 00 01 	movb   $0x1,0x200bae(%rip)        # 601028 <__TMC_END__>
  40047a:	f3 c3                	repz retq 
  40047c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400480 <frame_dummy>:
  400480:	bf 58 0e 60 00       	mov    $0x600e58,%edi
  400485:	48 83 3f 00          	cmpq   $0x0,(%rdi)
  400489:	75 05                	jne    400490 <frame_dummy+0x10>
  40048b:	eb 93                	jmp    400420 <register_tm_clones>
  40048d:	0f 1f 00             	nopl   (%rax)
  400490:	b8 00 00 00 00       	mov    $0x0,%eax
  400495:	48 85 c0             	test   %rax,%rax
  400498:	74 f1                	je     40048b <frame_dummy+0xb>
  40049a:	55                   	push   %rbp
  40049b:	48 89 e5             	mov    %rsp,%rbp
  40049e:	ff d0                	callq  *%rax
  4004a0:	5d                   	pop    %rbp
  4004a1:	e9 7a ff ff ff       	jmpq   400420 <register_tm_clones>

00000000004004a6 <syscall1>:
  4004a6:	55                   	push   %rbp
  4004a7:	48 89 e5             	mov    %rsp,%rbp
  4004aa:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  4004ae:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  4004b2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4004b6:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  4004ba:	0f 05                	syscall 
  4004bc:	90                   	nop
  4004bd:	5d                   	pop    %rbp
  4004be:	c3                   	retq   

00000000004004bf <main>:
  4004bf:	55                   	push   %rbp
  4004c0:	48 89 e5             	mov    %rsp,%rbp
  4004c3:	be 00 00 00 00       	mov    $0x0,%esi
  4004c8:	bf 3c 00 00 00       	mov    $0x3c,%edi
  4004cd:	e8 d4 ff ff ff       	callq  4004a6 <syscall1>
  4004d2:	90                   	nop
  4004d3:	5d                   	pop    %rbp
  4004d4:	c3                   	retq   
  4004d5:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4004dc:	00 00 00 
  4004df:	90                   	nop

00000000004004e0 <__libc_csu_init>:
  4004e0:	41 57                	push   %r15
  4004e2:	41 56                	push   %r14
  4004e4:	41 89 ff             	mov    %edi,%r15d
  4004e7:	41 55                	push   %r13
  4004e9:	41 54                	push   %r12
  4004eb:	4c 8d 25 56 09 20 00 	lea    0x200956(%rip),%r12        # 600e48 <__frame_dummy_init_array_entry>
  4004f2:	55                   	push   %rbp
  4004f3:	48 8d 2d 56 09 20 00 	lea    0x200956(%rip),%rbp        # 600e50 <__init_array_end>
  4004fa:	53                   	push   %rbx
  4004fb:	49 89 f6             	mov    %rsi,%r14
  4004fe:	49 89 d5             	mov    %rdx,%r13
  400501:	4c 29 e5             	sub    %r12,%rbp
  400504:	48 83 ec 08          	sub    $0x8,%rsp
  400508:	48 c1 fd 03          	sar    $0x3,%rbp
  40050c:	e8 7f fe ff ff       	callq  400390 <_init>
  400511:	48 85 ed             	test   %rbp,%rbp
  400514:	74 20                	je     400536 <__libc_csu_init+0x56>
  400516:	31 db                	xor    %ebx,%ebx
  400518:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40051f:	00 
  400520:	4c 89 ea             	mov    %r13,%rdx
  400523:	4c 89 f6             	mov    %r14,%rsi
  400526:	44 89 ff             	mov    %r15d,%edi
  400529:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40052d:	48 83 c3 01          	add    $0x1,%rbx
  400531:	48 39 dd             	cmp    %rbx,%rbp
  400534:	75 ea                	jne    400520 <__libc_csu_init+0x40>
  400536:	48 83 c4 08          	add    $0x8,%rsp
  40053a:	5b                   	pop    %rbx
  40053b:	5d                   	pop    %rbp
  40053c:	41 5c                	pop    %r12
  40053e:	41 5d                	pop    %r13
  400540:	41 5e                	pop    %r14
  400542:	41 5f                	pop    %r15
  400544:	c3                   	retq   
  400545:	90                   	nop
  400546:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40054d:	00 00 00 

0000000000400550 <__libc_csu_fini>:
  400550:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400554 <_fini>:
  400554:	48 83 ec 08          	sub    $0x8,%rsp
  400558:	48 83 c4 08          	add    $0x8,%rsp
  40055c:	c3                   	retq   
