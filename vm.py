#!/usr/bin/env python
import sys, itertools, argparse
from array import array

CHARS = {
    0: 'NUL', 1: 'SOH', 2: 'STX', 3: 'ETX', 4: 'EOT', 5: 'ENQ', 6: 'ACK', 7: 'BEL',
    8: 'BS', 9: 'HT', 10: 'NL', 11: 'VT', 12: 'NP', 13: 'CR', 14: 'SO', 15: 'SI',
    16: 'DLE', 17: 'DC1', 18: 'DC2', 19: 'DC3', 20: 'DC4', 21: 'NAK', 22: 'SYN', 23: 'ETB',
    24: 'CAN', 25: 'EM', 26: 'SUB', 27: 'ESC', 28: 'FS', 29: 'GS', 30: 'RS', 31: 'US',
    32: 'SP'
}

class VmException(Exception): pass
class VmHalted(VmException): pass
class UndefinedOpcode(VmException): pass
class InvalidAddress(VmException): pass
class InvalidRegister(VmException): pass
class InvalidValue(VmException): pass

class RegisterBank(object):
    def __init__(self):
        self.registers = array('H', [0, 0, 0, 0, 0, 0, 0, 0])

    def __getitem__(self, reg):
        return self.registers[reg]

    def __setitem__(self, reg, value):
        self.registers[reg] = value % 32768

class Memory(object):
    def __init__(self, registers):
        self.registers = registers
        self.memory = array('H', itertools.repeat(0, 0x10000))

    def __getitem__(self, address):
        try:
            return self.memory[address]
        except IndexError:
            raise InvalidAddress("Address %s is invalid" % address)

    def __setitem__(self, address, value):
        if 0 <= address <= 32767:
            self.memory[address] = value % 32768
        elif 32768 <= address <= 32775:
            self.registers[address - 32768] = value
        else:
            raise InvalidAddress("Address %s is neither memory nor register" % address)

    def read(self, start, length):
        return self.memory[start:start + length]

class Stack(object):
    def __init__(self):
        self.stack = array('H')

    def push(self, value):
        self.stack.append(value)

    def pop(self):
        return self.stack.pop()

class VirtualMachine:
    ops = {
        # opcode: ('name', args)
        0: ('halt', 0),
        1: ('set', 2),
        2: ('push', 1),
        3: ('pop', 1),
        4: ('eq', 3),
        5: ('gt', 3),
        6: ('jmp', 1),
        7: ('jt', 2),
        8: ('jf', 2),
        9: ('add', 3),
        10: ('mult', 3),
        11: ('mod', 3),
        12: ('and', 3),
        13: ('or', 3),
        14: ('not', 2),
        15: ('rmem', 2),
        16: ('wmem', 2),
        17: ('call', 1),
        18: ('ret', 0),
        19: ('out', 1),
        20: ('in', 1),
        21: ('noop', 0),
    }

    def __init__(self, trace=None, dump=None):
        self.registers = RegisterBank()
        self.memory = Memory(self.registers)
        self.stack = Stack()
        self.pc = 0
        self.trace = file(trace, 'w') if trace else None
        self.dump = dump

    def load(self, filename):
        code_array = array('H')
        code_str = file(filename, 'rb').read()
        code_array.fromstring(code_str)
        size = len(code_array)
        self.memory.memory[0:size] = code_array
        return size

    def execute(self):
        try:
            while 1:
                op_name, args = self.fetch_instruction(self.pc)

                if self.trace is not None:
                    # Print disassembly of instruction
                    self.trace.write('%s: %s    ; %s\n' % (
                        self.pc,
                        self.disassemble_instruction(op_name, args),
                        ' '.join(map(str, self.memory.read(self.pc, 1 + len(args))))
                    ))

                op_fn = getattr(self, 'op_%s' % op_name)
                self.pc += 1 + len(args)
                op_fn(*args)

                if self.trace is not None:
                    self.trace.write('    reg: %s\n' % ' '.join(map(str, self.registers.registers)))
                    self.trace.write('    stk: %s\n' % ' '.join(map(str, self.stack.stack)))

        except VmHalted:
            return
        except KeyboardInterrupt:
            if self.dump is not None:
                self.memory.memory.tofile(file(self.dump, 'wb'))
            raise

    def fetch_instruction(self, addr):
        opcode = self.memory[addr]
        try:
            op_name, num_args = self.ops[opcode]
        except KeyError:
            raise UndefinedOpcode("Opcode %s not defined" % opcode)

        # Read operands from memory following opcode
        args = self.memory.read(addr + 1, num_args)
        return op_name, args

    def value(self, value):
        if 0 <= value <= 32767:
            return value

        if 32768 <= value <= 32775:
            return self.registers[value - 32768]

        raise InvalidValue("Value %s is invalid as a number or a register" % value)

    def op_halt(self):
        raise VmHalted

    def op_set(self, reg, value):
        self.registers[reg - 32768] = self.value(value)

    def op_push(self, value):
        value = self.value(value)
        self.stack.push(value)

    def op_pop(self, addr):
        self.memory[addr] = self.stack.pop()

    def op_eq(self, a, b, c):
        b = self.value(b)
        c = self.value(c)
        self.memory[a] = 1 if b == c else 0

    def op_gt(self, a, b, c):
        b = self.value(b)
        c = self.value(c)
        self.memory[a] = 1 if b > c else 0

    def op_jmp(self, addr):
        addr = self.value(addr)
        self.pc = addr

    def op_jt(self, a, addr):
        a = self.value(a)
        addr = self.value(addr)
        if a:
            self.pc = addr

    def op_jf(self, a, addr):
        a = self.value(a)
        addr = self.value(addr)
        if a == 0:
            self.pc = addr

    def op_add(self, a, b, c):
        b = self.value(b)
        c = self.value(c)
        self.memory[a] = b + c

    def op_mult(self, a, b, c):
        b = self.value(b)
        c = self.value(c)
        self.memory[a] = b * c

    def op_mod(self, a, b, c):
        b = self.value(b)
        c = self.value(c)
        self.memory[a] = b % c

    def op_and(self, a, b, c):
        b = self.value(b)
        c = self.value(c)
        self.memory[a] = b & c

    def op_or(self, a, b, c):
        b = self.value(b)
        c = self.value(c)
        self.memory[a] = b | c

    def op_not(self, a, b):
        b = self.value(b)
        self.memory[a] = ~b

    def op_rmem(self, a, b):
        b = self.value(b)
        self.memory[a] = self.memory[b]

    def op_wmem(self, a, b):
        a = self.value(a)
        b = self.value(b)
        self.memory[a] = b

    def op_call(self, addr):
        addr = self.value(addr)
        self.stack.push(self.pc)
        self.pc = addr

    def op_ret(self):
        self.pc = self.stack.pop()

    def op_out(self, char):
        char = self.value(char)
        sys.stdout.write(chr(char))

    def op_in(self, addr):
        self.memory[addr] = ord(sys.stdin.read(1))

    def op_noop(self):
        pass

    def disassemble(self, addr, length):
        end = addr + length
        while addr < end:
            try:
                op_name, args = self.fetch_instruction(addr)
                print '%s: %s' % (addr, self.disassemble_instruction(op_name, args))
                addr += 1 + len(args)
            except UndefinedOpcode:
                print '%s: ???' % addr
                addr += 1

    def disassemble_instruction(self, op_name, args):
        return '%s %s' % (
            op_name,
            ', '.join(map(self.disassemble_operand, args))
        )

    def disassemble_operand(self, value):
        if 0 <= value <= 32767:
            if value < 128:
                return '%s (%s)' % (value, CHARS.get(value, chr(value)))
            else:
                return str(value)

        if 32768 <= value <= 32775:
            return 'R%s' % (value - 32768)

        return '%s (INVALID)' % value

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Synacor Challenge VM')
    parser.add_argument('--trace', '-t', nargs=1, metavar='FILE', default=[None],
        help="Trace every instruction execution to FILE")
    parser.add_argument('--dump', '-d', nargs=1, metavar='FILE', default=[None],
        help="Dump memory to FILE on ^C")
    parser.add_argument('code', nargs=1, metavar='CODE', help="Bytecode file to execute")
    args = parser.parse_args()

    vm = VirtualMachine(trace=args.trace[0], dump=args.dump[0])
    code_size = vm.load(args.code[0])
    try:
        vm.execute()
    except KeyboardInterrupt:
        print "Exited"
