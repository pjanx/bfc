// Non-optimizing Brainfuck compiler generating binaries for Linux on x86-64;
// gofmt has been tried, with disappointing results
package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

const ( RIGHT = iota; LEFT; INC; DEC; IN; OUT; BEGIN; END )

var info = []struct {
	grouped bool
	name    string
}{
	{true, "RIGHT"},
	{true, "LEFT"},
	{true, "INC"},
	{true, "DEC"},
	{false, "IN"},
	{false, "OUT"},
	{false, "BEGIN"},
	{false, "END"},
}

type instruction struct {
	command int
	arg     int
}

// Dump internal representation to a file for debugging purposes
func dump(filename string, irb []instruction) error {
	out, err := os.Create(filename)
	if err != nil {
		return err
	}

	indent := 0
	for _, x := range irb {
		if x.command == END {
			indent--
		}
		for i := 0; i < indent; i++ {
			out.WriteString("  ")
		}
		out.WriteString(info[x.command].name)
		if info[x.command].grouped {
			fmt.Fprintf(out, " %d", x.arg)
		}
		out.WriteString("\n")
		if x.command == BEGIN {
			indent++
		}
	}
	if err = out.Close(); err != nil {
		return err
	}
	return nil
}

// Decode a Brainfuck program into internal representation,
// coalescing identical commands together as the most basic optimization
func decode(program []byte) (irb []instruction) {
	for _, c := range program {
		var command int
		switch c {
		case '>': command = RIGHT
		case '<': command = LEFT
		case '+': command = INC
		case '-': command = DEC
		case '.': command = OUT
		case ',': command = IN
		case '[': command = BEGIN
		case ']': command = END
		default:  continue
		}

		if len(irb) == 0 || !info[command].grouped ||
			irb[len(irb)-1].command != command {
			irb = append(irb, instruction{command, 1})
		} else {
			irb[len(irb)-1].arg++
		}
	}
	return
}

// Match loop commands so that we know where to jump
func pairLoops(irb []instruction) error {
	nesting := 0
	stack := make([]int, len(irb))
	for i, x := range irb {
		switch x.command {
		case BEGIN:
			stack[nesting] = i
			nesting++
		case END:
			if nesting <= 0 {
				return errors.New("unbalanced loops")
			}
			nesting--
			irb[stack[nesting]].arg = i + 1
			irb[i].arg = stack[nesting] + 1
		}
	}
	if nesting != 0 {
		return errors.New("unbalanced loops")
	}
	return nil
}

// --- Code generation ---------------------------------------------------------

type codegen struct {
	buf []byte
}

// Convert an arbitrary integral value up to 8 bytes long to little endian
func le(unknown interface{}) []byte {
	// Trying hard to avoid reflect.Value.Int/Uint
	formatted := fmt.Sprintf("%d", unknown)

	var v uint64
	if unsigned, err := strconv.ParseUint(formatted, 10, 64); err == nil {
		v = unsigned
	} else if signed, err := strconv.ParseInt(formatted, 10, 64); err == nil {
		v = uint64(signed)
	} else {
		panic("cannot convert to number")
	}
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56)}
}

func (a *codegen) append(v []byte)           { a.buf = append(a.buf, v...) }
func (a *codegen) code(v string) *codegen    { a.append([]byte(v)); return a }
func (a *codegen) db(v interface{}) *codegen { a.append(le(v)[:1]); return a }
func (a *codegen) dw(v interface{}) *codegen { a.append(le(v)[:2]); return a }
func (a *codegen) dd(v interface{}) *codegen { a.append(le(v)[:4]); return a }
func (a *codegen) dq(v interface{}) *codegen { a.append(le(v)[:8]); return a }

const (
	ElfCodeAddr = 0x400000 // Where the code is loaded in memory
	ElfDataAddr = 0x800000 // Where the tape is placed in memory
)

const (
	SYS_READ  = 0
	SYS_WRITE = 1
	SYS_EXIT  = 60
)

func codegenAmd64(irb []instruction) []byte {
	offsets := make([]int, len(irb)+1)
	a := codegen{}

	a.code("\xB8").dd(ElfDataAddr)                // mov rax, "ElfCodeAddr"
	a.code("\x30\xDB")                            // xor bl, bl

	for i, x := range irb {
		offsets[i] = len(a.buf)
		if x.command == LEFT || x.command == RIGHT {
			a.code("\x88\x18")                    // mov [rax], bl
		}
		switch x.command {
		case RIGHT: a.code("\x48\x05").dd(x.arg)  // add rax, "arg"
		case LEFT:  a.code("\x48\x2D").dd(x.arg)  // sub rax, "arg"
		case INC:   a.code("\x80\xC3").db(x.arg)  // add bl, "arg"
		case DEC:   a.code("\x80\xEB").db(x.arg)  // sub bl, "arg"
		case OUT:   a.code("\xE8").dd(0)          // call "write"
		case IN:    a.code("\xE8").dd(0)          // call "read"
		case BEGIN:
			// test bl, bl; jz "offsets[arg]"
			a.code("\x84\xDB" + "\x0F\x84").dd(0)
		case END:
			// test bl, bl; jnz "offsets[arg]"
			a.code("\x84\xDB" + "\x0F\x85").dd(0)
		}
		if x.command == LEFT || x.command == RIGHT {
			a.code("\x8A\x18")                    // mov bl, [rax]
		}
	}
	// When there is a loop at the end we need to be able to jump past it
	offsets[len(irb)] = len(a.buf)

	// Write an epilog which handles all the OS interfacing
	//
	// System V x86-64 ABI:
	//   rax <-> both syscall number and return value
	//   args -> rdi, rsi, rdx, r10, r8, r9
	//   trashed <- rcx, r11

	a.code("\xB8").dd(SYS_EXIT)  // mov eax, 0x3c
	a.code("\x48\x31\xFF")       // xor rdi, rdi
	a.code("\x0F\x05")           // syscall

	fatal := len(a.buf)
	a.code("\x48\x89\xF7")       // mov rdi, rsi -- use the string in rsi
	a.code("\x30\xC0")           // xor al, al -- look for the nil byte
	a.code("\x48\x31\xC9")       // xor rcx, rcx
	a.code("\x48\xF7\xD1")       // not rcx -- start from -1
	a.code("\xFC" + "\xF2\xAE")  // cld; repne scasb -- decrement until found
	a.code("\x48\xF7\xD1")       // not rcx
	a.code("\x48\x8D\x51\xFF")   // lea rdx, [rcx-1] -- save length in rdx
	a.code("\xB8").dd(SYS_WRITE) // mov eax, "SYS_WRITE"
	a.code("\xBF").dd(2)         // mov edi, "STDERR_FILENO"
	a.code("\x0F\x05")           // syscall

	a.code("\xB8").dd(SYS_EXIT)  // mov eax, "SYS_EXIT"
	a.code("\xBF").dd(1)         // mov edi, "EXIT_FAILURE"
	a.code("\x0F\x05")           // syscall

	read := len(a.buf)
	a.code("\x50")               // push rax -- save tape position
	a.code("\xB8").dd(SYS_READ)  // mov eax, "SYS_READ"
	a.code("\x48\x89\xC7")       // mov rdi, rax -- STDIN_FILENO
	a.code("\x66\x6A\x00")       // push word 0 -- the default value for EOF
	a.code("\x48\x89\xE6")       // mov rsi, rsp -- the char starts at rsp
	a.code("\xBA").dd(1)         // mov edx, 1 -- count
	a.code("\x0F\x05")           // syscall
	a.code("\x66\x5B")           // pop bx

	a.code("\x48\x83\xF8\x00")   // cmp rax, 0
	a.code("\x48\x8D\x35").dd(4) // lea rsi, [rel read_message]
	a.code("\x7C")               // jl "fatal_offset" -- write failure message
	a.db(fatal - len(a.buf) - 1)
	a.code("\x58")               // pop rax -- restore tape position
	a.code("\xC3")               // ret
	a.code("fatal: read failed\n\x00")

	write := len(a.buf)
	a.code("\x50")               // push rax -- save tape position
	a.code("\xB8").dd(SYS_WRITE) // mov eax, "SYS_WRITE"
	a.code("\x48\x89\xC7")       // mov rdi, rax -- STDOUT_FILENO
	a.code("\x66\x53")           // push bx
	a.code("\x48\x89\xE6")       // mov rsi, rsp -- the char starts at rsp
	a.code("\xBA").dd(1)         // mov edx, 1 -- count
	a.code("\x0F\x05")           // syscall
	a.code("\x66\x5B")           // pop bx

	a.code("\x48\x83\xF8\x00")   // cmp rax, 0
	a.code("\x48\x8D\x35").dd(4) // lea rsi, [rel write_message]
	a.code("\x7C")               // jl "fatal_offset" -- write failure message
	a.db(fatal - len(a.buf) - 1)
	a.code("\x58")               // pop rax -- restore tape position
	a.code("\xC3")               // ret
	a.code("fatal: write failed\n\x00")

	// Now that we know where each instruction is, fill in relative jumps
	for i, x := range irb {
		// This must accurately reflect the code generators
		target, fixup := 0, offsets[i]
		if x.command == BEGIN || x.command == END {
			fixup += 4
			target = offsets[x.arg]
		} else if x.command == IN {
			fixup += 1
			target = read
		} else if x.command == OUT {
			fixup += 1
			target = write
		} else {
			continue
		}
		copy(a.buf[fixup:], le(target - fixup - 4)[:4])
	}
	return a.buf
}

// --- Main --------------------------------------------------------------------

func main() {
	var err error
	if len(os.Args) > 3 {
		log.Fatalf("usage: %s [INPUT-FILE] [OUTPUT-FILE]", os.Args[0])
	}

	input := os.Stdin
	if len(os.Args) > 1 {
		if input, err = os.Open(os.Args[1]); err != nil {
			log.Fatalf("%s", err)
		}
	}

	outputPath := "a.out"
	if len(os.Args) > 2 {
		outputPath = os.Args[2]
	}

	program, err := ioutil.ReadAll(input)
	input.Close()
	if err != nil {
		log.Fatalf("can't read program: %s", err)
	}

	irb := decode(program)
	// ... various optimizations could be performed here if we give up brevity
	pairLoops(irb)
	dump("ir-dump.txt", irb)

	code := codegenAmd64(irb)
	a := codegen{}

	// TODO: also use the constants in package "debug/elf"

	const (
		ElfHeaderSize       = 64        // size of the ELF header
		ElfProgramEntrySize = 56        // size of a program header
		ElfSectionEntrySize = 64        // size of a section header
		ElfPrologSize       = ElfHeaderSize + 2*ElfProgramEntrySize
	)

	// ELF header
	a.code("\x7FELF\x02\x01\x01")       // ELF, 64-bit, little endian, v1
	// Unix System V ABI, v0, padding
	a.code("\x00\x00" + "\x00\x00\x00\x00\x00\x00\x00")
	a.dw(2).dw(62).dd(1)                // executable, x86-64, v1
	a.dq(ElfCodeAddr + ElfPrologSize)   // entry point address

	// We only append section headers with debugging info with DEBUG
	a.dq(ElfHeaderSize).dq(0)           // program, section header offset
	a.dd(0)                             // no processor-specific flags
	a.dw(ElfHeaderSize)                 // ELF header size
	a.dw(ElfProgramEntrySize).dw(2)     // program hdr tbl entry size, count
	a.dw(ElfSectionEntrySize).dw(0)     // section hdr tbl entry size, count
	a.dw(0)                             // no section index for strings

	// Program header for code
	// The entry point address seems to require alignment, so map start of file
	a.dd(1).dd(5)                       // PT_LOAD, PF_R | PF_X
	a.dq(0)                             // offset within the file
	a.dq(ElfCodeAddr)                   // address in virtual memory
	a.dq(ElfCodeAddr)                   // address in physical memory
	a.dq(ElfPrologSize + len(code))     // length within the file
	a.dq(ElfPrologSize + len(code))     // length within memory
	a.dq(4096)                          // segment alignment

	// Program header for the tape
	a.dd(1).dd(6)                       // PT_LOAD, PF_R | PF_W
	a.dq(0)                             // offset within the file
	a.dq(ElfDataAddr)                   // address in virtual memory
	a.dq(ElfDataAddr)                   // address in physical memory
	a.dq(0)                             // length within the file
	a.dq(1 << 20)                       // one megabyte of memory
	a.dq(4096)                          // segment alignment

	a.buf = append(a.buf, code...)
	if err = ioutil.WriteFile(outputPath, a.buf, 0777); err != nil {
		log.Fatalf("%s", err)
	}
}
