#!/usr/bin/python
from cmd import Cmd
import argparse, shlex
from vm import VirtualMachine, BreakpointHit, VmHalted

class DebugShell(Cmd):
    prompt = 'VM> '

    def __init__(self):
        Cmd.__init__(self)
        self.vm = VirtualMachine()

    def do_load(self, arg):
        """load <filename>
        Load the VM bytecode from <filename> to address 0"""
        args = shlex.split(arg)
        code_size = self.vm.load(args[0])
        print "Loaded %s words" % code_size

    def do_pc(self, arg):
        """pc <addr>
        Set the program counter to address <addr>"""
        args = shlex.split(arg)
        self.vm.pc = int(args[0])
        print "PC set to %s" % self.vm.pc

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

    def do_break(self, arg):
        """break [<addr>]
        Set a breakpoint at <addr>, or list all breakpoints"""
        args = shlex.split(arg)
        if args:
            addr = int(args[0])
            self.vm.breakpoints.add(addr)
            print "Breakpoint set at %s" % addr
        else:
            print "Breakpoints:"
            print '\n'.join(map(str, self.vm.breakpoints))

    def do_unbreak(self, arg):
        """unbreak [<addr>]
        Remove breakpoint from <addr> or remove all breakpoints"""
        args = shlex.split(arg)
        if args:
            addr = int(args[0])
            self.vm.breakpoints.remove(addr)
            print "Breakpoint removed from %s" % addr
        else:
            self.vm.breakpoints.clear()
            print "All breakpoints removed"

    def do_run(self, arg):
        """run
        Execute from current PC"""
        try:
            self.vm.execute()
        except KeyboardInterrupt:
            print "Stopped by ^C -- state may be weird"
        except BreakpointHit:
            print "Breakpoint hit at %s" % self.vm.pc
        except VmHalted:
            print "Halt"

    def do_EOF(self, arg):
        print
        return True

if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='Synacor Challenge VM')
    # parser.add_argument('--trace', '-t', nargs=1, metavar='FILE', default=[None],
    #     help="Trace every instruction execution to FILE")
    # parser.add_argument('--dump', '-d', nargs=1, metavar='FILE', default=[None],
    #     help="Dump memory to FILE on ^C")
    # parser.add_argument('code', nargs=1, metavar='CODE', help="Bytecode file to execute")
    # args = parser.parse_args()

    shell = DebugShell()
    shell.cmdloop("Synacor Challenge VM debugging shell")

    # def fudge_r7(signal, frame):
    #     print "Updating R7"
    #     vm.registers[7] = 3

    # signal.signal(signal.SIGUSR1, fudge_r7)
