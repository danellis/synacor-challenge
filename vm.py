#!/usr/bin/env python
import sys, itertools
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
            value = self.memory[address]
        except IndexError:
            raise InvalidAddress("Address %s is invalid" % address)
        return self.real_value(value)

    def __setitem__(self, address, value):
        value = self.real_value(value)
        try:
            self.memory[address] = value % 32768
        except IndexError:
            raise InvalidAddress("Address %s is invalid" % address)

    def read(self, start, length):
        return map(self.real_value, self.memory[start:start + length])

    def real_value(self, value):
        if 0 <= value <= 32767:
            return value

        if 32768 <= value <= 32775:
            reg = value - 32768
            if reg > 7:
                raise InvalidRegister("Register %s is invalid" % reg)
            return self.registers[reg]

        raise InvalidValue("Value %s is invalid as a number or a register" % value)

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

    def __init__(self):
        self.registers = RegisterBank()
        self.memory = Memory(self.registers)
        self.stack = Stack()
        self.pc = 0

    def load(self, filename):
        code = array('H')
        code.fromstring(file(filename, 'rb').read())
        self.memory.memory[0:len(code)] = code

    def execute(self):
        try:
            while 1:
                # Get next operation
                opcode = self.memory[self.pc]
                try:
                    op_name, num_args = self.ops[opcode]
                except KeyError:
                    raise UndefinedOpcode("Opcode %s not defined" % opcode)
                op_fn = getattr(self, 'op_%s' % op_name)

                # Read operands from memory following opcode
                args = self.memory.read(self.pc + 1, num_args)

                # Execute instruction, and update PC with the returned address
                # or the next instruction if None is returned
                self.pc = op_fn(*args) or (self.pc + 1 + num_args)
        except VmHalted:
            print "Halted"

    def op_halt(self):
        raise VmHalted("Halted")

    def op_set(self, reg, value):
        self.registers[reg] = value

    def op_push(self, value):
        self.stack.push(value)

    def op_pop(self, addr):
        self.memory[addr] = self.stack.pop()

    def op_eq(self, a, b, c):
        self.memory[a] = 1 if b == c else 0

    def op_gt(self, a, b, c):
        self.memory[a] = 1 if b > c else 0

    def op_jmp(self, addr):
        return addr

    def op_jt(self, a, addr):
        if a:
            return addr

    def op_jf(self, a, addr):
        if a == 0:
            return addr

    def op_add(self, a, b, c):
        self.memory[a] = b + c

    def op_mult(self, a, b, c):
        self.memory[a] = b * c

    def op_mod(self, a, b, c):
        self.memory[a] = b % c

    def op_and(self, a, b, c):
        self.memory[a] = b & c

    def op_or(self, a, b, c):
        self.memory[a] = b | c

    def op_not(self, a, b):
        self.memory[a] = ~b

    def op_rmem(self, a, b):
        self.memory[a] = self.memory[b]

    def op_wmem(self, a, b):
        self.memory[a] = b

    def op_call(self, addr):
        self.stack.push(self.pc + 2)
        return addr

    def op_ret(self):
        return self.stack.pop()

    def op_out(self, char):
        sys.stdout.write(chr(char))

    def op_in(self, addr):
        self.memory[addr] = ord(sys.stdin.read(1))

    def op_noop(self):
        pass

if __name__ == '__main__':
    vm = VirtualMachine()
    vm.load('challenge.bin')
    vm.execute()
