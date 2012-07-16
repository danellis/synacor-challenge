#!/usr/bin/python
from cmd import Cmd
import argparse, shlex
from vm import VirtualMachine, VmHalted, UndefinedOpcode

CHARS = {
    0: 'NUL', 1: 'SOH', 2: 'STX', 3: 'ETX', 4: 'EOT', 5: 'ENQ', 6: 'ACK', 7: 'BEL',
    8: 'BS', 9: 'HT', 10: 'NL', 11: 'VT', 12: 'NP', 13: 'CR', 14: 'SO', 15: 'SI',
    16: 'DLE', 17: 'DC1', 18: 'DC2', 19: 'DC3', 20: 'DC4', 21: 'NAK', 22: 'SYN', 23: 'ETB',
    24: 'CAN', 25: 'EM', 26: 'SUB', 27: 'ESC', 28: 'FS', 29: 'GS', 30: 'RS', 31: 'US',
    32: 'SP'
}

class DebugException(Exception): pass
class BreakpointHit(DebugException): pass

class DebugShell(Cmd):
    prompt = 'VM> '

    def __init__(self):
        Cmd.__init__(self)
        self.vm = VirtualMachine()
        self.trace_file = None
        self.breakpoints = set()

    def do_load(self, arg):
        """load <filename>
        Load the VM bytecode from <filename> to address 0"""
        args = shlex.split(arg)
        code_size = self.vm.load(args[0])
        print "Loaded %s words" % code_size
        self.vm.pc = 0
        self.print_current_instruction()

    def do_pc(self, arg):
        """pc <addr>
        Set the program counter to address <addr>"""
        args = shlex.split(arg)
        self.vm.pc = int(args[0])
        self.print_current_instruction()

    def do_reg(self, arg):
        """reg [<n> ...]
        Print the values of the specified (or all) registers"""
        args = shlex.split(arg)
        regs = map(int, args) if args else range(0, 8)
        for r in regs:
            print "R%s: %s" % (r, self.vm.registers[r])

    def do_set(self, arg):
        """set <reg> <value>
        Set register <reg> to <value>"""
        args = shlex.split(arg)
        reg = int(args[0])
        value = int(args[1])
        self.vm.registers[reg] = value

    def do_peek(self, arg):
        """peek <addr>
        Print value at memory address <addr>"""
        args = shlex.split(arg)
        addr = int(args[0])
        print "%s: %s" % (addr, self.vm.memory[addr])

    def do_poke(self, arg):
        """poke <addr> <value>
        Write <value> to memory address <addr>"""
        args = shlex.split(arg)
        addr = int(args[0])
        value = int(args[1])
        self.vm.memory[addr] = value

    def do_str(self, arg):
        """str <addr>
        Print the length-prefixed string at <addr>"""
        args = shlex.split(arg)
        addr = int(args[0])
        length = self.vm.memory[addr]
        return ''.join(map(chr, self.vm.memory[addr + 1:addr + 1 + length]))

    def do_step(self, arg):
        """step
        Execute only the next instruction"""
        self.vm.step()
        self.print_current_instruction()

    def do_break(self, arg):
        """break [<addr>]
        Set a breakpoint at <addr>, or list all breakpoints"""
        args = shlex.split(arg)
        if args:
            addr = int(args[0])
            self.breakpoints.add(addr)
            print "Breakpoint set at %s" % addr
        else:
            print "Breakpoints:"
            print '\n'.join(['%s: %s' % (a, self.disassemble_one(a)) for a in self.breakpoints])

    def do_unbreak(self, arg):
        """unbreak [<addr>]
        Remove breakpoint from <addr> or remove all breakpoints"""
        args = shlex.split(arg)
        if args:
            addr = int(args[0])
            self.breakpoints.remove(addr)
            print "Breakpoint removed from %s" % addr
        else:
            self.breakpoints.clear()
            print "All breakpoints removed"

    def do_run(self, arg):
        """run
        Execute from current PC"""
        try:
            while 1:
                if self.trace_file is not None:
                    self.trace()
                self.vm.step()
                if self.vm.pc in self.breakpoints:
                    raise BreakpointHit
        except KeyboardInterrupt:
            print "Stopped by ^C -- state may be weird"
            self.print_current_instruction()
        except BreakpointHit:
            print "Breakpoint hit at %s" % self.vm.pc
            self.print_current_instruction()
        except VmHalted:
            print "Halt"

    def do_dis(self, arg):
        """dis <addr> [<count>]
        Disassemble one or <count> instructions starting at <addr>"""
        args = shlex.split(arg)
        addr = int(args[0])
        count = int(args[1]) if len(args) > 1 else 1
        self.disassemble(addr, count)

    def do_ss(self, arg):
        """ss <string>
        Search for <string> in memory"""
        args = shlex.split(arg)
        needle = ' '.join(args)
        # FIXME: This is probably horrendously inefficient
        mem = ''.join(map(lambda c: chr(c if c < 256 else 0), self.vm.memory.memory))
        index = mem.find(needle)
        print index

    def do_trace(self, arg):
        """ss off|<filename>
        Turn off tracing, or begin tracing to <filename>"""
        args = shlex.split(arg)
        filename = args[0]
        if self.trace_file is not None:
            self.trace_file.close()
        if filename == 'off':
            self.trace_file = None
            print "Tracing off"
        else:
            self.trace_file = file(filename, 'w')
            print "Tracing to file %s" % filename

    def do_dump(self, arg):
        """dump <filename>
        Dump memory contents into <filename>"""
        args = shlex.split(arg)
        filename = args[0]
        self.vm.memory.memory.tofile(file(filename, 'wb'))


    def do_out_locations(self, arg):
        locs = self.vm.out_locations.items()
        sorted_locs = sorted(locs, key=lambda x: x[0])
        for loc, chars in sorted_locs:
            print '%s: %s' % (loc, ''.join(chars))
    def do_EOF(self, arg):
        print
        return True

    def print_current_instruction(self):
        print '%s: %s' % (self.vm.pc, self.disassemble_one(self.vm.pc))

    def trace(self):
        self.trace_file.write('%s: %s\n' % (self.vm.pc, self.disassemble_one(self.vm.pc)))

    def disassemble(self, addr, count):
        while count:
            try:
                op_name, args = self.vm.fetch_instruction(addr)
                print '%s: %s' % (addr, self.disassemble_instruction(op_name, args))
                addr += 1 + len(args)
            except UndefinedOpcode:
                print '%s: ???' % addr
                addr += 1
            count -= 1

    def disassemble_one(self, addr):
        return self.disassemble_instruction(*self.vm.fetch_instruction(addr))

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
    parser = argparse.ArgumentParser(description='Synacor Challenge VM debugger')
    parser.add_argument('--init', '-i', nargs=1, metavar='FILE', default=[None],
        help="Execute commands from FILE before starting shell")
    parser.add_argument('code', nargs='?', metavar='CODE', default=None,
        help="Bytecode file to load")
    args = parser.parse_args()

    shell = DebugShell()
    print "Synacor Challenge VM debugging shell"
    if args.code:
        shell.onecmd('load %s' % args.code)
    if args.init[0]:
        for line in file(args.init[0], 'r'):
            shell.onecmd(line)
    shell.cmdloop()

    # def fudge_r7(signal, frame):
    #     print "Updating R7"
    #     vm.registers[7] = 3

    # signal.signal(signal.SIGUSR1, fudge_r7)
