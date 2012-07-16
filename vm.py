#!/usr/bin/env python
import sys, itertools, argparse, signal
from array import array

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
        self.call_stack = []
        self.out_locations = {}
        self.calls = {}

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
                self.step()
        except VmHalted:
            return

    def step(self):
        op_name, args = self.fetch_instruction(self.pc)
        op_fn = getattr(self, 'op_%s' % op_name)
        self.pc += 1 + len(args)
        op_fn(*args)

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
        self.call_stack.append(addr)
        calls = self.calls.setdefault(addr, [])
        calls.append(self.pc - 2)
        self.stack.push(self.pc)
        self.pc = addr

    def op_ret(self):
        self.call_stack.pop()
        self.pc = self.stack.pop()

    def op_out(self, char):
        char = chr(self.value(char))
        addr = self.pc - 2
        chars = self.out_locations.setdefault(addr, [])
        chars.append(char)
        sys.stdout.write(char)

    def op_in(self, addr):
        try:
            char = sys.stdin.read(1)
        except IOError:
            char = sys.stdin.read(1)
        self.memory[addr] = ord(char)

    def op_noop(self):
        pass

if __name__ == '__main__':
    vm = VirtualMachine()
    code_size = vm.load(sys.argv[1])

    try:
        vm.execute()
    except KeyboardInterrupt:
        print "Exited"
