package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/bnagy/gapstone"
)

const MAX_LOOKBEHIND = 10

func FindSyscall(insns []gapstone.Instruction) int {
	if len(insns) == 0 {
		panic("syscall too small")
	}
	for i := len(insns) - 1; i > 0; i-- {
		insn := insns[i]
		fmt.Printf("0x%x\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		firstOp := insn.X86.Operands[0]
		secondOp := insn.X86.Operands[1]
		switch insn.Mnemonic {
		case "mov":
			if firstOp.Type != gapstone.X86_OP_REG {
				continue
			}
			switch firstOp.Reg {
			case gapstone.X86_REG_RAX, gapstone.X86_REG_EAX:
				if secondOp.Type != gapstone.X86_OP_IMM {
					fmt.Printf("RAX is not immediate!!! %+v\n", secondOp)
					return -1
				}
				return int(secondOp.Imm)
			default:
				continue
			}
		case "xor":
			if firstOp.Type != gapstone.X86_OP_REG || secondOp.Type != gapstone.X86_OP_REG {
				continue
			}
			switch firstOp.Reg {
			case gapstone.X86_REG_RAX, gapstone.X86_REG_EAX:
				if firstOp.Reg == secondOp.Reg {
					return 0
				}
			default:
				continue
			}
		}
	}
	log.Fatal("Rax not found")
	return -1
}

func main() {

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_64,
	)

	if err == nil {

		defer engine.Close()

		file, err := os.Open(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		data, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}

		engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

		insns, err := engine.Disasm(
			data,    // code buffer
			0x10000, // starting address
			0,       // insns to disassemble, 0 for all
		)

		if err != nil {
			log.Fatalf("Disassembly error: %v", err)
		}
		for i, insn := range insns {
			if insn.Mnemonic == "syscall" {
				var behind []gapstone.Instruction
				if i >= MAX_LOOKBEHIND {
					behind = insns[i-10 : i]
				} else {
					behind = insns[0:i]
				}
				call_nbr := FindSyscall(behind)
				fmt.Println("Syscall ", call_nbr)
			}
		}
		return

	}
	log.Fatalf("Failed to initialize engine: %v", err)
}
