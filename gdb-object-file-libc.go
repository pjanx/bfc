// Non-optimizing Brainfuck compiler generating object files for *nix on x86-64
// with debugging information mapping instructions onto an IR dump.
// gofmt has been tried, with disappointing results.
// codegen{} is also pretty ugly in the way it works but damn convenient.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	// Let's not repeat all those constants here onstants
	"debug/dwarf"
	"debug/elf"
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

	b := make([]byte, 8)
	if unsigned, err := strconv.ParseUint(formatted, 10, 64); err == nil {
		binary.LittleEndian.PutUint64(b, unsigned)
	} else if signed, err := strconv.ParseInt(formatted, 10, 64); err == nil {
		binary.LittleEndian.PutUint64(b, uint64(signed))
	} else {
		panic("cannot convert to number")
	}
	return b
}

func (a *codegen) append(v []byte)           { a.buf = append(a.buf, v...) }
func (a *codegen) code(v string) *codegen    { a.append([]byte(v)); return a }
func (a *codegen) db(v interface{}) *codegen { a.append(le(v)[:1]); return a }
func (a *codegen) dw(v interface{}) *codegen { a.append(le(v)[:2]); return a }
func (a *codegen) dd(v interface{}) *codegen { a.append(le(v)[:4]); return a }
func (a *codegen) dq(v interface{}) *codegen { a.append(le(v)[:8]); return a }

type fixup struct { offset, addend int; typ uint32; }

// The linker may _add_ to offsets even with explicit addends (.rela)
func codegenAmd64(irb []instruction) (code []byte, offsets []int,
	fixups map[string][]fixup) {
	offsets = make([]int, len(irb)+1)
	a := codegen{}

	fixups = map[string][]fixup{}
	abs := func(name string) {
		fixups[name] = append(fixups[name],
			fixup{len(a.buf),  0, uint32(elf.R_X86_64_32)})
		a.dd(0)
	}
	call := func(name string) {
		a.code("\xE8")
		fixups[name] = append(fixups[name],
			fixup{len(a.buf), -4, uint32(elf.R_X86_64_PC32)})
		a.dd(0)
	}

	a.code("\xB8"); abs("tape")                   // mov rax, "tape"
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

	a.code("\x48\x31\xFF")       // xor rdi, rdi
	call("exit")                 // call [exit]

	read := len(a.buf)
	a.code("\x50")               // push rax -- save tape position
	call("getchar")              // call [getchar]
	a.code("\x88\xC3")           // mov bl, al

	a.code("\x83\xF8\x00")       // cmp eax, 0
	a.code("\x7D").db(2)         // jge over the next instruction
	a.code("\xB3\x00")           // mov bl, 0 -- translate EOF to 0
	a.code("\x58")               // pop rax -- restore tape position
	a.code("\xC3")               // ret

	write := len(a.buf)
	a.code("\x50")               // push rax -- save tape position
	a.code("\x66\x53")           // push bx
	a.code("\x48\x0F\xB6\xFB")   // movzx rdi, bl
	call("putchar")              // call [putchar]
	a.code("\x66\x5B")           // pop bx

	a.code("\x83\xF8\x00")       // cmp eax, 0
	a.code("\x7C").db(2)         // jl over the return
	a.code("\x58")               // pop rax -- restore tape position
	a.code("\xC3")               // ret

	a.code("\x48\x8b\x34\x25")   // mov rsi, ["stderr"]
	abs("stderr")
	a.code("\x8D\x3D").dd(15)    // lea edi, [rel write_message]
	call("fputs")                // call [fputs]
	a.code("\xBF").dd(1)         // mov edi, "EXIT_FAILURE"
	call("exit")                 // call [exit]
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
	return a.buf, offsets, fixups
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
	code, offsets, fixups := codegenAmd64(irb)

// - - ELF generation  - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Now that we know how long the machine code is, we can write the header.
	// Note that for PIE we would need to depend on the dynamic linker, so no.
	//
	// Recommended reading:
	//   http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
	//   man 5 elf
	//
	// In case of unexpected gdb problems, also see:
	//   DWARF4.pdf
	//   https://sourceware.org/elfutils/DwarfLint
	//   http://wiki.osdev.org/DWARF

	const (
		ElfHeaderSize       = 64        // Size of the ELF header
		ElfProgramEntrySize = 56        // Size of a program header
		ElfSectionEntrySize = 64        // Size of a section header
		ElfDataSize         = 1 << 20   // Tape length
	)

	codeOffset := ElfHeaderSize
	pieces := [][]byte{code}
	position := codeOffset + len(code)

// - - Sections  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	sh := codegen{}
	shCount := 0

	// This section is created on the go as we need to name other sections
	stringTable := codegen{}

	// A null section is needed by several GNU tools

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code("\x00")
	sh.dd(elf.SHT_NULL).dq(0).dq(0)     // Type, no flags, no memory address
	sh.dq(0).dq(0)                      // Byte offset, byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shCount++

// - - Text  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".text\x00")
	sh.dd(elf.SHT_PROGBITS)
	sh.dq(elf.SHF_ALLOC | elf.SHF_EXECINSTR)
	sh.dq(0)                            // Memory address
	sh.dq(codeOffset)                   // Byte offset
	sh.dq(len(code))                    // Byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shTextIndex := shCount
	shCount++

// - - BSS - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".bss\x00")
	sh.dd(elf.SHT_NOBITS)
	sh.dq(elf.SHF_ALLOC | elf.SHF_WRITE)
	sh.dq(0)                            // Memory address
	sh.dq(0)                            // Byte offset
	sh.dq(ElfDataSize)                  // Byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shBSSIndex := shCount
	shCount++

// - - Symbol table  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	symtab := codegen{}
	symstrtab := codegen{}

	// A null symbol is needed by several GNU tools

	symtab.dd(len(symstrtab.buf))       // Index for symbol name
	symstrtab.code("\x00")
	symtab.db(elf.ST_INFO(elf.STB_LOCAL, elf.STT_NOTYPE))
	symtab.db(elf.STV_DEFAULT)          // Default visibility rules
	symtab.dw(0).dq(0).dq(0)            // No section, no offset, no length

	symbols := map[string]uint32{}
	nextSymbol := uint32(1)
	nameSymbol := func(name string) {
		symtab.dd(len(symstrtab.buf))
		symstrtab.code(name).code("\x00")
		symbols[name] = nextSymbol
		nextSymbol++
	}

	nameSymbol("tape")
	symtab.db(elf.ST_INFO(elf.STB_LOCAL, elf.STT_OBJECT))
	symtab.db(elf.STV_DEFAULT)          // Default visibility rules
	symtab.dw(shBSSIndex)               // Relative to section .bss
	symtab.dq(0)                        // Right at the start of BSS
	symtab.dq(ElfDataSize)              // Span the entire section

	// It can't be _start since that is already defined somewhere in libc
	// and we'd like CC to figure out where the dynamic linker is at least
	nameSymbol("main")
	symtab.db(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC))
	symtab.db(elf.STV_DEFAULT)          // Default visibility rules
	symtab.dw(shTextIndex)              // Relative to section .text
	symtab.dq(0)                        // Right at the start of code
	symtab.dq(len(code))                // Span the entire section

	// Create records for undefined symbols to be resolved by the linker
	for k, _ := range fixups {
		if _, ok := symbols[k]; ok {
			continue
		}
		nameSymbol(k)
		symtab.db(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_NOTYPE))
		symtab.db(elf.STV_DEFAULT)      // Default visibility rules
		symtab.dw(0).dq(0).dq(0)        // No section, no offset, no length
	}

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".symstrtab\x00")
	sh.dd(elf.SHT_STRTAB).dq(0).dq(0)   // Type, no flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(symstrtab.buf))           // Byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shSymstrtabIndex := shCount
	shCount++

	pieces = append(pieces, symstrtab.buf)
	position += len(symstrtab.buf)

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".symtab\x00")
	sh.dd(elf.SHT_SYMTAB).dq(0).dq(0)   // Type, no flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(symtab.buf))              // Byte size
	sh.dd(shSymstrtabIndex).dd(2)       // Link, info: index of first non-local
	sh.dq(0).dq(24)                     // No alignment, entry size
	shSymtabIndex := shCount
	shCount++

	pieces = append(pieces, symtab.buf)
	position += len(symtab.buf)

// - - Text relocation records - - - - - - - - - - - - - - - - - - - - - - - - -

	// ld.gold doesn't support SHT_REL, with SHT_RELA it overrides the target.
	// ld.bfd addends to the target even with SHT_RELA.
	// Thus, with SHT_RELA the target needs to be all zeros to be portable.

	textRel := codegen{}
	for k, v := range fixups {
		for _, r := range v {
			textRel.dq(r.offset).dq(elf.R_INFO(symbols[k], r.typ)).dq(r.addend)
		}
	}

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".rela.text\x00")
	sh.dd(elf.SHT_RELA)                 // Type
	sh.dq(elf.SHF_INFO_LINK).dq(0)      // Flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(textRel.buf))             // Byte size
	sh.dd(shSymtabIndex).dd(shTextIndex)// Link, info
	sh.dq(0).dq(24)                     // No alignment, entry size
	shCount++

	pieces = append(pieces, textRel.buf)
	position += len(textRel.buf)

// - - Debug line  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	const (
		opcodeBase = 13  // Offset by DWARF4 standard opcodes
		lineBase   = 0   // We don't need negative line indexes
		lineRange  = 2   // Either we advance a line or not (we always do)
	)

	// FIXME: we use db() a lot instead of a proper un/signed LEB128 encoder;
	//   that means that values > 127/63 or < 0 would break it;
	//   see Appendix C to DWARF4.pdf for an algorithm

	lineProgram := codegen{}
	// Extended opcode DW_LNE_set_address to reset the PC to the start of code
	lineProgram.db(0).db(1 + 8).db(2)
	lineAddressOff := len(lineProgram.buf)
	lineProgram.dq(0)
	if len(irb) > 0 {
		lineProgram.db(opcodeBase + offsets[0] * lineRange)
	}
	// The epilog, which is at the very end of the offset array, is included
	for i := 1; i <= len(irb); i++ {
		size := offsets[i] - offsets[i - 1]
		lineProgram.db(opcodeBase + (1 - lineBase) + size * lineRange)
	}
	// Extended opcode DW_LNE_end_sequence is mandatory at the end
	lineProgram.db(0).db(1).db(1)

	lineHeader := codegen{}
	lineHeader.db(1)                    // Minimum instruction length
	lineHeader.db(1)                    // Maximum operations per instruction
	lineHeader.db(1)                    // default_is_stmt
	lineHeader.db(lineBase)
	lineHeader.db(lineRange)

	lineHeader.db(opcodeBase)
	// Number of operands for all standard opcodes (1..opcodeBase-1)
	opcodeLengths := []byte{0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1}
	lineHeader.buf = append(lineHeader.buf, opcodeLengths...)

	// include_directories []string \x00
	lineHeader.db(0)
	// file_names []struct{base string; dir u8; modified u8; length u8} \x00
	lineHeader.code("ir-dump.txt\x00").db(0).db(0).db(0).db(0)

	lineEntry := codegen{}
	lineEntry.dw(4)                     // .debug_line version number
	lineEntry.dd(len(lineHeader.buf))
	lineEntry.buf = append(lineEntry.buf, lineHeader.buf...)
	lineAddressOff += len(lineEntry.buf)
	lineEntry.buf = append(lineEntry.buf, lineProgram.buf...)

	debugLine := codegen{}
	debugLine.dd(len(lineEntry.buf))
	lineAddressOff += len(debugLine.buf)
	debugLine.buf = append(debugLine.buf, lineEntry.buf...)

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".debug_line\x00")
	sh.dd(elf.SHT_PROGBITS).dq(0).dq(0) // Type, no flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(debugLine.buf))           // Byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shLineIndex := shCount
	shCount++

	pieces = append(pieces, debugLine.buf)
	position += len(debugLine.buf)

// - - Debug line relocation records - - - - - - - - - - - - - - - - - - - - - -

	lineRel := codegen{}
	lineRel.dq(lineAddressOff).
		dq(elf.R_INFO(symbols["main"], uint32(elf.R_X86_64_64)))

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".rel.debug_line\x00")
	sh.dd(elf.SHT_REL)                  // Type
	sh.dq(elf.SHF_INFO_LINK).dq(0)      // Flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(lineRel.buf))             // Byte size
	sh.dd(shSymtabIndex).dd(shLineIndex)// Link, info
	sh.dq(0).dq(16)                     // No alignment, entry size
	shCount++

	pieces = append(pieces, lineRel.buf)
	position += len(lineRel.buf)

// - - Debug abbreviations - - - - - - - - - - - - - - - - - - - - - - - - - - -

	const (
		formAddr      = 0x01            // Pointer size
		formSecOffset = 0x17            // DWARF size
	)

	debugAbbrev := codegen{}
	debugAbbrev.db(1)                   // Our abbreviation code
	debugAbbrev.db(dwarf.TagCompileUnit)
	debugAbbrev.db(0)                   // DW_CHILDREN_no
	debugAbbrev.db(dwarf.AttrLowpc).db(formAddr)
	debugAbbrev.db(dwarf.AttrHighpc).db(formAddr)
	debugAbbrev.db(dwarf.AttrStmtList).db(formSecOffset)
	debugAbbrev.db(0).db(0)             // End of attributes
	debugAbbrev.db(0)                   // End of abbreviations

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".debug_abbrev\x00")
	sh.dd(elf.SHT_PROGBITS).dq(0).dq(0) // Type, no flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(debugAbbrev.buf))         // Byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shCount++

	pieces = append(pieces, debugAbbrev.buf)
	position += len(debugAbbrev.buf)

// - - Debug info  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	cuEntry := codegen{}
	cuEntry.dw(4)                       // .debug_info version number
	cuEntry.dd(0)                       // Offset into .debug_abbrev
	cuEntry.db(8)                       // Pointer size

	// Single compile unit as per .debug_abbrev
	cuEntry.db(1)
	infoStartOff := len(cuEntry.buf)
	cuEntry.dq(0)
	infoEndOff := len(cuEntry.buf)
	cuEntry.dq(len(code))
	cuEntry.dd(0)

	debugInfo := codegen{}
	debugInfo.dd(len(cuEntry.buf))
	infoStartOff += len(debugInfo.buf)
	infoEndOff += len(debugInfo.buf)
	debugInfo.buf = append(debugInfo.buf, cuEntry.buf...)

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".debug_info\x00")
	sh.dd(elf.SHT_PROGBITS).dq(0).dq(0) // Type, no flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(debugInfo.buf))           // Byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shInfoIndex := shCount
	shCount++

	pieces = append(pieces, debugInfo.buf)
	position += len(debugInfo.buf)

// - - Debug info relocation records - - - - - - - - - - - - - - - - - - - - - -

	infoRel := codegen{}
	infoRel.dq(infoStartOff).
		dq(elf.R_INFO(symbols["main"], uint32(elf.R_X86_64_64)))
	infoRel.dq(infoEndOff).
		dq(elf.R_INFO(symbols["main"], uint32(elf.R_X86_64_64)))

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".rel.debug_info\x00")
	sh.dd(elf.SHT_REL)                  // Type
	sh.dq(elf.SHF_INFO_LINK).dq(0)      // Flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(infoRel.buf))             // Byte size
	sh.dd(shSymtabIndex).dd(shInfoIndex)// Link, info
	sh.dq(0).dq(16)                     // No alignment, entry size
	shCount++

	pieces = append(pieces, infoRel.buf)
	position += len(infoRel.buf)

// - - Section names and section table - - - - - - - - - - - - - - - - - - - - -

	sh.dd(len(stringTable.buf))         // Index for the name of the section
	stringTable.code(".shstrtab\x00")
	sh.dd(elf.SHT_STRTAB).dq(0).dq(0)   // Type, no flags, no memory address
	sh.dq(position)                     // Byte offset
	sh.dq(len(stringTable.buf))         // Byte size
	sh.dd(0).dd(0)                      // No link, no info
	sh.dq(0).dq(0)                      // No alignment, no entry size
	shCount++

	pieces = append(pieces, stringTable.buf)
	position += len(stringTable.buf)

	pieces = append(pieces, sh.buf)
	// Don't increment the position, we want to know where section headers start

// - - Final assembly of parts - - - - - - - - - - - - - - - - - - - - - - - - -

	bin := codegen{}

	// ELF header
	bin.code("\x7FELF\x02\x01\x01")     // ELF, 64-bit, little endian, v1
	// Unix System V ABI, v0, padding
	bin.code("\x00\x00" + "\x00\x00\x00\x00\x00\x00\x00")
	// The BFD linker will happily try to link ET_EXEC though
	bin.dw(elf.ET_REL).dw(elf.EM_X86_64).dd(elf.EV_CURRENT)
	bin.dq(0)                           // Entry point address
	bin.dq(0)                           // Program header offset
	bin.dq(position)                    // Section header offset
	bin.dd(0)                           // No processor-specific flags
	bin.dw(ElfHeaderSize)               // ELF header size
	bin.dw(ElfProgramEntrySize)         // Program header table entry size
	bin.dw(0)                           // Program header table entry count
	bin.dw(ElfSectionEntrySize)         // Section header table entry size
	bin.dw(shCount)                     // Section header table entry count
	bin.dw(shCount - 1)                 // Section index for strings

	for _, x := range pieces {
		bin.buf = append(bin.buf, x...)
	}
	if err = ioutil.WriteFile(outputPath, bin.buf, 0777); err != nil {
		log.Fatalf("%s", err)
	}
}
