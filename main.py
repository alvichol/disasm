import sys


class UnsupportedFileFormat(Exception):
    def __init__(self, txt):
        self.text = txt


class UnsupportedCommand(Exception):
    def __init__(self, txt):
        self.text = txt


class Parser:
    def __init__(self, byte_list):
        self.byte_list = byte_list

    def get_num(self, start, length):
        num = 0
        for i in range(start + length - 1, start - 1, -1):
            num <<= 8
            num += self.byte_list[i]
        return num

    def get_string(self, start):
        txt = []
        for i in range(start, len(self.byte_list)):
            if self.byte_list[i] == 0:
                return ''.join(txt)
            txt.append(chr(self.byte_list[i]))
        return ''.join(txt)

    def get_param(self, start, size):
        arr = []
        for sz in size:
            arr.append(self.get_num(start, sz))
            start += sz
        return arr

    def get_header(self):
        params = self.get_param(0, [16, 2, 2, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2])
        if not params[0] == int('00010101464c457f', 16) or not params[1] == 2:
            raise UnsupportedFileFormat('')
        return Header(params[6], params[12], params[13])

    def get_section(self, start):
        params = self.get_param(start, [4, 4, 4, 4, 4, 4, 4, 4, 4, 4])
        return Section(*params)

    def get_symtab_entry(self, start, offset):
        params = self.get_param(start, [4, 4, 4, 1, 1, 2])
        name = self.get_string(params[0] + offset)
        return SymtabEntry(*params, name)

    def get_command(self, start):
        num = self.get_param(start, [4])[0]
        bits = []
        for i in range(32):
            bits.append(str(num % 2))
            num //= 2
        string = ''.join(bits)
        opcode = string[0:7][::-1]
        if not opcode[5:] == "11" or opcode[2:] == "11111":
            raise UnsupportedCommand('')
        rd = string[7:12][::-1]
        f3 = string[12:15][::-1]
        rs1 = string[15:20][::-1]
        imm = string[20:32][::-1]
        return Command(opcode, rd, f3, rs1, imm, string)


def get_bind(num):
    bind = {
        0: 'LOCAL',
        1: 'GLOBAL',
        2: 'WEAK',
        13: 'LOPROC',
        15: 'HIPROC'
    }
    return bind[num]


def get_type(num):
    type_ = {
        0: 'NOTYPE',
        1: 'OBJECT',
        2: 'FUNC',
        3: 'SECTION',
        4: 'FILE',
        13: 'LOPROC',
        14: 'HIPROC'
    }
    return type_[num]


def get_vis(num):
    vis = {
        0: 'DEFAULT',
        1: 'INTERNAL',
        2: 'HIDDEN',
        3: 'PROTECTED'
    }
    return vis[num]


def get_special(num):
    spec = {
        0: 'UNDEF',
        0xff00: 'LOPROC',
        0xff1f: 'HIPROC',
        0xfff1: 'ABS',
        0xfff2: 'COMMON',
        0xffff: 'HIRESERVE'
    }
    if num not in spec:
        return str(num)
    return spec[num]


def get_reg(num):
    reg = {
        0: "zero",
        1: "ra",
        2: "sp",
        3: "gp",
        4: "tp",
        5: "t0",
        6: "t1",
        7: "t2",
        8: "s0",
        9: "s1",
        10: "a0",
        11: "a1",
        12: "a2",
        13: "a3",
        14: "a4",
        15: "a5",
        16: "a6",
        17: "a7",
        18: "s2",
        19: "s3",
        20: "s4",
        21: "s5",
        22: "s6",
        23: "s7",
        24: "s8",
        25: "s9",
        26: "s10",
        27: "s11",
        28: "t3",
        29: "t4",
        30: "t5",
        31: "t6"
    }
    return reg[num]


class Header:  # ELF file header
    def __init__(self, shoff, shnum, shstrndx):
        self.shoff = shoff
        self.shnum = shnum
        self.shstrndx = shstrndx


class Section:  # Section header table
    def __init__(self, name, sh_type, flags, addr, offset, size, link, info, addralign, entersize):
        self.name = name
        self.sh_type = sh_type
        self.flags = flags
        self.addr = addr
        self.offset = offset
        self.size = size
        self.link = link
        self.info = info
        self.addralign = addralign
        self.entersize = entersize


class SymtabEntry:
    def __init__(self, name, value, size, info, other, shndx, str_name):
        self.name = name
        self.value = value
        self.size = size
        self.info = info
        self.other = other
        self.shndx = shndx
        self.str_name = str_name
        self.bind = get_bind(info >> 4)
        self.etype = get_type(info & 0xf)
        self.vis = get_vis(other & 0x3)
        self.index = get_special(shndx)

    def to_string(self, idx):
        return "[%4i] 0x%-15X %5i %-8s %-8s %-8s %6s %s\n" % (
            idx,
            self.value,
            self.size,
            self.etype,
            self.bind,
            self.vis,
            self.index,
            self.str_name
        )


labels = {}
labels_cnt = 0


def get_label(string, addr):
    global labels, labels_cnt
    if addr in labels:
        return string + " <" + labels[addr] + ">"
    labels[addr] = "L" + str(labels_cnt)
    labels_cnt += 1
    return string + " <" + labels[addr] + ">"


class Command:
    def __init__(self, opcode, rd, f3, rs1, imm, comm_string):
        self.op = opcode
        self.rd = int(rd, 2)
        self.f3 = f3
        self.rs1 = int(rs1, 2)
        self.imm = imm
        self.comm_string = comm_string
        self.full_code = int(comm_string[::-1], 2)

    def substr(self, start, end):
        return self.comm_string[start:end + 1][::-1]

    def get_format2(self, addr, name, arg1, arg2):
        return "   %05x:\t%08x\t%7s\t%s, %s" % (addr, self.full_code, name, arg1, arg2)

    def get_format3(self, addr, name, arg1, arg2, arg3):
        return "   %05x:\t%08x\t%7s\t%s, %s, %s" % (addr, self.full_code, name, arg1, arg2, arg3)

    def get_unknown(self, addr):
        return "   %05x:\t%08x\t%7s" % (addr, self.full_code, "unknown")

    def get_command(self, addr):
        imm = int(self.imm, 2) - 2 * 2048 * int(self.substr(31, 31))
        if self.op == "0110111":
            const = int(self.substr(12, 30), 2) - int(self.substr(31, 31)) * (2 ** 19)
            return self.get_format2(addr, "lui", get_reg(self.rd), hex(const))
        elif self.op == "0010111":
            const = int(self.substr(12, 30), 2) - int(self.substr(31, 31)) * (2 ** 19)
            return self.get_format2(addr, "auipc", get_reg(self.rd), hex(const))
        elif self.op == "1101111":
            const = int(self.substr(31, 31) + self.substr(12, 19) + self.substr(20, 20) + self.substr(21, 30), 2)
            const *= 2
            const -= 2 ** 21 * int(self.substr(31, 31))
            new_addr = addr + const
            ans = self.get_format2(addr, "jal", get_reg(self.rd), hex(new_addr))
            return get_label(ans, new_addr)
        elif self.op == "1100111":
            return self.get_format2(addr, "jalr", get_reg(self.rd), hex(imm) + "(" + get_reg(self.rs1) + ")")
        elif self.op == "0000011":
            get_name = {
                "000": "lb",
                "001": "lh",
                "010": "lw",
                "100": "lbu",
                "101": "lhu"
            }
            if self.f3 in get_name:
                nm = get_name[self.f3]
                return self.get_format2(addr, nm, get_reg(self.rd), str(imm) + "(" + get_reg(self.rs1) + ")")
            return self.get_unknown(addr)
        elif self.op == "1100011":
            get_name = {
                "000": "beq",
                "001": "bne",
                "100": "blt",
                "101": "bge",
                "110": "bltu",
                "111": "bgeu"
            }
            if self.f3 not in get_name:
                return self.get_unknown(addr)
            const = int(self.substr(31, 31) + self.substr(7, 7) + self.substr(25, 30) + self.substr(8, 11), 2)
            const *= 2
            const -= 4096 * 2 * int(self.substr(31, 31))
            new_addr = addr + const
            rs2 = int(self.substr(20, 24), 2)
            ans = self.get_format3(addr, get_name[self.f3], get_reg(self.rs1), get_reg(rs2), hex(new_addr))
            return get_label(ans, new_addr)
        elif self.op == "0100011":
            get_name = {
                "000": "sb",
                "001": "sh",
                "010": "sw"
            }
            if self.f3 not in get_name:
                return self.get_unknown(addr)
            rs2 = int(self.substr(20, 24), 2)
            const = -4096 * int(self.substr(31, 31), 2) + int(self.substr(25, 31) + self.substr(7, 11), 2)
            return self.get_format2(addr, get_name[self.f3], get_reg(rs2), str(const) + "(" + get_reg(self.rs1) + ")")
        elif self.op == "0010011":
            get_name = {
                "000": "addi",
                "001": "slli",
                "010": "slti",
                "011": "sltiu",
                "100": "xori",
                "110": "ori",
                "111": "andi"
            }
            if self.f3 not in get_name:
                if self.f3 == "101":
                    imm = int(self.substr(20, 25), 2)
                    if int(self.substr(30, 30)) == 0:
                        get_name["101"] = "srli"
                    else:
                        get_name["101"] = "srai"
                else:
                    return self.get_unknown(addr)
            return self.get_format3(addr, get_name[self.f3], get_reg(self.rd), get_reg(self.rs1), imm)
        elif self.op == "0110011":
            rs2 = int(self.substr(20, 24), 2)
            if int(self.substr(25, 31), 2) == 1:
                get_name = {
                    "000": "mul",
                    "001": "mulh",
                    "010": "mulhsu",
                    "011": "mulhu",
                    "100": "div",
                    "101": "divu",
                    "110": "rem",
                    "111": "remu"
                }
            else:
                get_name = {
                    "001": "sll",
                    "010": "slt",
                    "011": "sltu",
                    "100": "xor",
                    "110": "or",
                    "111": "and"
                }
                if int(self.substr(30, 30)) == 0:
                    get_name["000"] = "add"
                    get_name["101"] = "srl"
                else:
                    get_name["000"] = "sub"
                    get_name["101"] = "sra"
            return self.get_format3(addr, get_name[self.f3], get_reg(self.rd), get_reg(self.rs1), get_reg(rs2))
        elif self.op == "1110011":
            if self.f3 == "000" and int(self.substr(20, 20)) == 0:
                return "   %05x:\t%08x\t%7s" % (addr, self.full_code, "ecall")
            elif self.f3 == "000":
                return "   %05x:\t%08x\t%7s" % (addr, self.full_code, "ebreak")
            return self.get_unknown(addr)
        return self.get_unknown(addr)


def main(args):
    fin = open(args[1], 'rb')
    byte_arr = list(fin.read())
    fin.close()

    prs = Parser(byte_arr)
    head = prs.get_header()

    sections = []
    for i in range(head.shnum):
        sections.append(prs.get_section(head.shoff + i * 40))

    name_table = sections[head.shstrndx]
    sym_off = 0
    sym_num = 0
    name_off = 0
    text_off = 0
    text_addr = 0
    command_num = 0
    sym_entries = []

    for section in sections:
        name = prs.get_string(section.name + name_table.offset)
        if name == '.symtab':
            sym_off = section.offset
            sym_num = section.size // 16
        elif name == '.strtab':
            name_off = section.offset
        elif name == '.text':
            text_off = section.offset
            text_addr = section.addr
            command_num = section.size // 4

    for i in range(sym_num):
        sym_entries.append(prs.get_symtab_entry(sym_off + i * 16, name_off))
        labels[sym_entries[i].value] = sym_entries[i].str_name

    commands = []
    start = text_off
    for i in range(command_num):
        commands.append(prs.get_command(start))
        start += 4

    start = text_addr
    parsed_commands = []
    for i in range(command_num):
        parsed_commands.append(commands[i].get_command(start))
        start += 4

    fout = open(args[2], 'w')
    fout.write('.text\n')

    start = text_addr
    for i in range(command_num):
        if start in labels:
            fout.write("%08x   <%s>:\n" % (start, labels[start]))
        fout.write(parsed_commands[i])
        fout.write('\n')
        start += 4

    fout.write('\n')
    fout.write('.symtab\n')
    fout.write('Symbol Value              Size Type     Bind     Vis       Index Name\n')

    for i in range(sym_num):
        fout.write(sym_entries[i].to_string(i))

    fout.close()


if __name__ == '__main__':
    try:
        main(sys.argv)
    except FileNotFoundError:
        print("File not found")
    except IndexError:
        print("No cmd arguments")
    except UnsupportedFileFormat:
        print("Unsupported file format")
    except UnsupportedCommand:
        print("Unsupported compressed and long commands")
