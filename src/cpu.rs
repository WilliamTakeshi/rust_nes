use crate::{bus::Bus, opcodes};
use std::{collections::HashMap, result};

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPage_X,
    ZeroPage_Y,
    Absolute,
    Absolute_X,
    Absolute_Y,
    Indirect_X,
    Indirect_Y,
    NoneAddressing,
}

const STACK: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;
const DEFAULT_CPU_STATUS: u8 = 0b0010_0100;

#[derive(Debug)]
pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub status: u8, // TODO: update status to use bitflags
    pub stack_pointer: u8,
    pub program_counter: u16,
    pub bus: Bus,
}

pub trait Mem {
    fn mem_read(&mut self, addr: u16) -> u8;

    fn mem_write(&mut self, addr: u16, data: u8);

    fn mem_read_u16(&mut self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }
}

impl Mem for CPU {
    fn mem_read(&mut self, addr: u16) -> u8 {
        self.bus.mem_read(addr)
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.bus.mem_write(addr, data)
    }
    fn mem_read_u16(&mut self, pos: u16) -> u16 {
        self.bus.mem_read_u16(pos)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        self.bus.mem_write_u16(pos, data)
    }
}

fn page_cross(addr1: u16, addr2: u16) -> bool {
    addr1 & 0xFF00 != addr2 & 0xFF00
}

impl CPU {
    pub fn new(bus: Bus) -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            register_y: 0,
            status: DEFAULT_CPU_STATUS,
            stack_pointer: STACK_RESET,
            program_counter: 0,
            bus: bus,
        }
    }

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.stack_pointer = STACK_RESET;
        self.status = DEFAULT_CPU_STATUS;

        self.program_counter = self.mem_read_u16(0x0599);
    }

    pub fn load(&mut self, program: Vec<u8>) {
        for i in 0..(program.len() as u16) {
            self.mem_write(0x0600 + i, program[i as usize]);
        }
        self.mem_write_u16(0x0599, 0x0600);
    }

    pub fn load_reset_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run()
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.program_counter = self.mem_read_u16(0x0599);
        self.run()
    }

    // fn interrupt(&mut self, interrupt: interrupt::Interrupt) {
    //     self.stack_push_u16(self.program_counter);
    //     let mut flag = self.status.clone();

    //     if interrupt.b_flag_mask & 0b010000 == 1 {
    //         flag = flag | 0b0001_0000;
    //     } else {
    //         flag = flag & 0b1110_1111;
    //     }

    //     if interrupt.b_flag_mask & 0b100000 == 1 {
    //         flag = flag | 0b0000_0010;
    //     } else {
    //         flag = flag & 0b1111_1101;
    //     }

    //     self.stack_push(flag.bits);
    //     self.status.insert(CpuFlags::INTERRUPT_DISABLE);

    //     self.bus.tick(interrupt.cpu_cycles);
    //     self.program_counter = self.mem_read_u16(interrupt.vector_addr);
    // }

    pub fn run(&mut self) {
        self.run_with_callback(|_| {});
    }

    pub fn run_with_callback<F>(&mut self, mut callback: F)
    where
        F: FnMut(&mut CPU),
    {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            // if let Some(_nmi) = self.bus.poll_nmi_status() {
            //     self.interrupt(interrupt::NMI);
            // }

            callback(self);
            let code = self.mem_read(self.program_counter);
            self.program_counter += 1;
            let program_counter_state = self.program_counter;

            let opscode = opcodes
                .get(&code)
                .expect(&format!("OpCode {:x} is not recognized", code));

            match code {
                /* ADC */
                0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => self.adc(&opscode.mode),
                /* AND */
                0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => self.and(&opscode.mode),
                /* ASL */
                0x0A => self.asl_accumulator(),
                0x06 | 0x16 | 0x0E | 0x1E => {
                    self.asl(&opscode.mode);
                }
                /* BCC */
                0x90 => self.branch(self.status & 0b0000_0001 == 0),
                /* BCS */
                0xB0 => self.branch(self.status & 0b0000_0001 > 0),
                /* BEQ */
                0xF0 => self.branch(self.status & 0b0000_0010 > 0),
                /* BMI */
                0x30 => self.branch(self.status & 0b1000_0000 > 0),
                /* BNE */
                0xD0 => self.branch(self.status & 0b0000_0010 == 0),
                /* BPL */
                0x10 => self.branch(self.status & 0b1000_0000 == 0),
                /* BVC */
                0x50 => self.branch(self.status & 0b01000000 == 0),
                /* BVS */
                0x70 => self.branch(self.status & 0b01000000 > 0),
                /* BIT */
                0x24 | 0x2C => self.bit(&opscode.mode),
                /* CLC */
                0x18 => self.clc(),
                /* CLD */
                0xD8 => self.cld(),
                /* CLI */
                0x58 => self.cli(),
                /* CLV */
                0xB8 => self.clv(),
                /* CMP */
                0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => self.cmp(&opscode.mode),
                /* CPX */
                0xE0 | 0xE4 | 0xEC => self.cpx(&opscode.mode),
                /* CPY */
                0xC0 | 0xC4 | 0xCC => self.cpy(&opscode.mode),
                /* DEC */
                0xC6 | 0xD6 | 0xCE | 0xDE => self.dec(&opscode.mode),
                /* DEX */
                0xCA => self.dex(),
                /* DEY */
                0x88 => self.dey(),
                /* EOR */
                0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 => self.eor(&opscode.mode),
                /* INC */
                0xE6 | 0xF6 | 0xEE | 0xFE => {
                    self.inc(&opscode.mode);
                }
                /* INX */
                0xE8 => self.inx(),
                /* INY */
                0xC8 => self.iny(),
                /* JMP Absolute */
                0x4c => {
                    let mem_address = self.mem_read_u16(self.program_counter);
                    self.program_counter = mem_address;
                }

                /* JMP Indirect */
                0x6c => {
                    let mem_address = self.mem_read_u16(self.program_counter);
                    // let indirect_ref = self.mem_read_u16(mem_address);
                    //6502 bug mode with with page boundary:
                    //  if address $3000 contains $40, $30FF contains $80, and $3100 contains $50,
                    // the result of JMP ($30FF) will be a transfer of control to $4080 rather than $5080 as you intended
                    // i.e. the 6502 took the low byte of the address from $30FF and the high byte from $3000

                    let indirect_ref = if mem_address & 0x00FF == 0x00FF {
                        let lo = self.mem_read(mem_address);
                        let hi = self.mem_read(mem_address & 0xFF00);
                        (hi as u16) << 8 | (lo as u16)
                    } else {
                        self.mem_read_u16(mem_address)
                    };

                    self.program_counter = indirect_ref;
                }

                /* JSR */
                0x20 => {
                    self.stack_push_u16(self.program_counter + 1);
                    let target_address = self.mem_read_u16(self.program_counter);
                    self.program_counter = target_address
                }
                /* LDA */
                0xA9 | 0xA5 | 0xB5 | 0xAD | 0xBD | 0xB9 | 0xA1 | 0xB1 => {
                    self.lda(&opscode.mode);
                }
                /* LDX */
                0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {
                    self.ldx(&opscode.mode);
                }
                /* LDY */
                0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {
                    self.ldy(&opscode.mode);
                }
                /* LSR */
                0x4A => self.lsr_accumulator(),
                0x46 | 0x56 | 0x4E | 0x5E => {
                    self.lsr(&opscode.mode);
                }
                /* NOP */
                0xEA => {}
                /* ORA */
                0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 => self.ora(&opscode.mode),
                /* PHA */
                0x48 => self.stack_push(self.register_a),
                /* PLA */
                0x68 => {
                    self.pla();
                }
                /* PHP */
                0x08 => {
                    self.php();
                }
                /* PLP */
                0x28 => {
                    self.plp();
                }
                /* ROL */
                0x2A => self.rol_accumulator(),
                0x26 | 0x36 | 0x2E | 0x3E => {
                    self.rol(&opscode.mode);
                }
                /* ROR */
                0x6A => self.ror_accumulator(),
                0x66 | 0x76 | 0x6E | 0x7E => {
                    self.ror(&opscode.mode);
                }
                /* RTI */
                0x40 => {
                    self.status = self.stack_pop();
                    self.status = self.status & 0b1110_1111;
                    self.status = self.status | 0b0010_0000;

                    self.program_counter = self.stack_pop_u16();
                }

                /* RTS */
                0x60 => {
                    self.program_counter = self.stack_pop_u16() + 1;
                }
                /* SBC */
                0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 => self.sbc(&opscode.mode),
                /* SEC */
                0x38 => self.sec(),
                /* SED */
                0xF8 => self.sed(),
                /* SEI */
                0x78 => self.sei(),
                /* STA */
                0x85 | 0x95 | 0x8D | 0x9D | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opscode.mode);
                }
                /* STX */
                0x86 | 0x96 | 0x8E => {
                    self.stx(&opscode.mode);
                }
                /* STY */
                0x84 | 0x94 | 0x8C => {
                    self.sty(&opscode.mode);
                }

                /* TAX */
                0xAA => self.tax(),
                /* TAY */
                0xA8 => self.tay(),
                /* TSX */
                0xBA => self.tsx(),
                /* TXA */
                0x8A => self.txa(),
                /* TXS */
                0x9A => self.txs(),
                /* TYA */
                0x98 => self.tya(),
                0x00 => {
                    return;
                }
                /* Undocumented Opcodes */
                /* ANC */
                0x0B | 0x2B => {
                    self.and(&opscode.mode);
                    if self.register_a & 0b1000_0000 > 0 {
                        self.status = self.status | 0b0000_0001;
                    } else {
                        self.status = self.status & 0b1111_1110;
                    }
                }
                /* AAX */
                0x87 | 0x97 | 0x83 | 0x8F => self.aax(&opscode.mode),
                /* ARR */
                0x6B => {
                    self.and(&AddressingMode::Immediate);
                    self.ror_accumulator();
                    // C is bit 6
                    if self.register_a & 0b0100_0000 > 0 {
                        self.status = self.status | 0b0000_0001;
                    } else {
                        self.status = self.status & 0b1111_1110;
                    }
                    // V is bit 6 xor bit 5
                    if (self.register_a & 0b0100_0000 > 0) ^ (self.register_a & 0b0010_0000 > 0) {
                        self.status = self.status | 0b0100_0000;
                    } else {
                        self.status = self.status & 0b1011_1111;
                    }
                }
                /* ASR */
                0x4B => {
                    // Equivalent to AND #i then LSR A
                    self.and(&AddressingMode::Immediate);
                    self.lsr_accumulator();
                }
                /* ATX */
                0xAB => {
                    // AND byte with accumulator, then transfer accumulator to X register.
                    self.and(&AddressingMode::Immediate);
                    self.tax();
                }
                /* AXA */
                0x9F | 0x93 => {
                    let (addr, page_cross) = self.get_operand_address(&opscode.mode);

                    // AND X register with accumulator then AND result with 7 and store in memory
                    let and = self.register_x & self.register_a & (addr >> 8) as u8;

                    self.mem_write(addr, and)
                }
                /* AXS */
                0xCB => {
                    let (addr, page_cross) = self.get_operand_address(&opscode.mode);
                    let data = self.mem_read(addr);

                    let and = self.register_a & self.register_x;
                    let result = and.wrapping_sub(data);

                    self.update_carry_flag(and >= data);
                    self.register_x = result;

                    self.update_zero_and_negative_flags(result);
                }
                /* DCP */
                0xC7 | 0xD7 | 0xCF | 0xDF | 0xDB | 0xC3 | 0xD3 => {
                    let (addr, page_cross) = self.get_operand_address(&opscode.mode);
                    let mut data = self.mem_read(addr);
                    data = data.wrapping_sub(1);
                    self.mem_write(addr, data);

                    if data <= self.register_a {
                        self.status = self.status | 0b0000_0001;
                    }

                    self.update_zero_and_negative_flags(self.register_a.wrapping_sub(data));
                }
                /* DOP */
                0x04 | 0x14 | 0x34 | 0x44 | 0x54 | 0x64 | 0x74 | 0x80 | 0x82 | 0x89 | 0xC2 | 0xD4 | 0xE2 | 0xF4  => {
                    let (_addr, page_cross) = self.get_operand_address(&opscode.mode);
                    if page_cross {
                        self.bus.tick(1);
                    }
                }
                /* ISC */
                0xE7 | 0xF7 | 0xEF | 0xFF | 0xFB | 0xE3 | 0xF3 => {
                    let data = self.inc(&opscode.mode);
                    self.sub_from_register_a(data);
                }
                /* KIL */
                0x02 | 0x12 | 0x22 | 0x32 | 0x42 | 0x52 | 0x62 | 0x72 | 0x92 | 0xB2 | 0xD2
                | 0xF2 => { /* Nothing */ }
                /* LAS */
                0xBB => {
                    let (addr, page_cross) = self.get_operand_address(&opscode.mode);
                    let mut data = self.mem_read(addr);
                    data = data & self.stack_pointer;
                    self.register_a = data;
                    self.register_x = data;
                    self.stack_pointer = data;
                    self.update_zero_and_negative_flags(data);
                }
                /* LAX */
                0xA7 | 0xB7 | 0xAF | 0xBF | 0xA3 | 0xB3 => {
                    let (addr, page_cross) = self.get_operand_address(&opscode.mode);
                    let data = self.mem_read(addr);
                    self.set_register_a(data);
                    self.register_x = self.register_a;
                }
                /* NOP */
                0x1A | 0x3A | 0x5A | 0x7A | 0xDA | 0xFA => {}
                /* RLA */
                0x27 | 0x37 | 0x2F | 0x3F | 0x3B | 0x23 | 0x33 => {
                    let data = self.rol(&opscode.mode);
                    self.and_with_register_a(data);
                }
                /* RRA */
                0x67 | 0x77 | 0x6F | 0x7F | 0x7B | 0x63 | 0x73 => {
                    let data = self.ror(&opscode.mode);
                    self.add_to_register_a(data);
                }
                /* SBC */
                0xEB => {
                    self.sbc(&opscode.mode);
                }
                /* SLO */
                0x07 | 0x17 | 0x0F | 0x1F | 0x1B | 0x03 | 0x13 => {
                    let data = self.asl(&opscode.mode);
                    self.or_with_register_a(data);
                }
                /* SRE */
                0x47 | 0x57 | 0x4F | 0x5F | 0x5B | 0x43 | 0x53 => {
                    let data = self.lsr(&opscode.mode);
                    self.xor_with_register_a(data);
                }
                /* SXA */
                0x9E => {
                    let data = self.lsr(&opscode.mode);
                    self.xor_with_register_a(data);
                }
                /* SYA */
                0x9C => {
                    let mem_address =
                        self.mem_read_u16(self.program_counter) + self.register_x as u16;
                    let data = self.register_y & ((mem_address >> 8) as u8 + 1);
                    self.mem_write(mem_address, data)
                }
                /* TOP */
                0x0C | 0x1C | 0x3C | 0x5C | 0x7C | 0xDC | 0xFC => { /* do nothing */ }
                /* XAA */
                0x8B => {
                    self.register_a = self.register_x;
                    self.update_zero_and_negative_flags(self.register_a);
                    let (addr, page_cross) = self.get_operand_address(&opscode.mode);
                    let data = self.mem_read(addr);
                    self.and_with_register_a(data);
                }
                /* XAS */
                0x9B => {
                    let data = self.register_a & self.register_x;
                    self.stack_pointer = data;
                    let mem_address =
                        self.mem_read_u16(self.program_counter) + self.register_y as u16;

                    let data = ((mem_address >> 8) as u8 + 1) & self.stack_pointer;
                    self.mem_write(mem_address, data)
                }
                _ => todo!(),
            }

            self.bus.tick(opscode.cycles);

            if program_counter_state == self.program_counter {
                self.program_counter += (opscode.bytes - 1) as u16;
            }
        }
    }

    // returns (address, page_cross flag)
    pub fn get_absolute_address(&mut self, mode: &AddressingMode, addr: u16) -> (u16, bool) {
        match mode {
            AddressingMode::ZeroPage => (self.mem_read(addr) as u16, false),

            AddressingMode::Absolute => (self.mem_read_u16(addr), false),

            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.register_x) as u16;
                (addr, false)
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(addr);
                let addr = pos.wrapping_add(self.register_y) as u16;
                (addr, false)
            }

            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(addr);
                let addr = base.wrapping_add(self.register_x as u16);
                (addr, page_cross(base, addr))
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(addr);
                let addr = base.wrapping_add(self.register_y as u16);
                (addr, page_cross(base, addr))
            }

            AddressingMode::Indirect_X => {
                let base = self.mem_read(addr);

                let ptr: u8 = (base as u8).wrapping_add(self.register_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                ((hi as u16) << 8 | (lo as u16), false)
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(addr);

                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.register_y as u16);
                (deref, page_cross(deref, deref_base))
            }

            _ => {
                panic!("mode {:?} is not supported", mode);
            }
        }
    }

    fn get_operand_address(&mut self, mode: &AddressingMode) -> (u16, bool) {
        match mode {
            AddressingMode::Immediate => (self.program_counter, false),
            _ => self.get_absolute_address(mode, self.program_counter),
        }
    }

    fn bit(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        let and = self.register_a & data;
        if and == 0 {
            self.status = self.status | 0b0000_0010;
        } else {
            self.status = self.status & 0b1111_1101;
        }

        if data & 0b1000_0000 > 0 {
            self.status = self.status | 0b1000_0000;
        } else {
            self.status = self.status & 0b0111_1111;
        }

        if data & 0b0100_0000 > 0 {
            self.status = self.status | 0b0100_0000;
        } else {
            self.status = self.status & 0b1011_1111;
        }
    }

    fn branch(&mut self, condition: bool) {
        if condition {
            self.bus.tick(1);

            let jump: i8 = self.mem_read(self.program_counter) as i8;
            let jump_addr = self
                .program_counter
                .wrapping_add(1)
                .wrapping_add(jump as u16);

            if self.program_counter.wrapping_add(1) & 0xFF00 != jump_addr & 0xFF00 {
                self.bus.tick(1);
            }

            self.program_counter = jump_addr;
        }
    }

    // TODO: Write cmp, cpx and cpy to a single function
    fn cmp(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        if page_cross {
            self.bus.tick(1);
        }
        self.update_zero_and_negative_flags(self.register_a.wrapping_sub(value));
        self.update_carry_flag(value <= self.register_a);
    }

    fn cpx(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        if page_cross {
            self.bus.tick(1);
        }
        self.update_zero_and_negative_flags(self.register_x.wrapping_sub(value));
        self.update_carry_flag(value <= self.register_x);
    }

    fn cpy(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        if page_cross {
            self.bus.tick(1);
        }
        self.update_zero_and_negative_flags(self.register_y.wrapping_sub(value));
        self.update_carry_flag(value <= self.register_y);
    }

    /// note: ignoring decimal mode
    /// http://www.righto.com/2012/12/the-6502-overflow-flag-explained.html
    fn add_to_register_a(&mut self, data: u8) {
        let sum = self.register_a as u16
            + data as u16
            + (if self.status & 0b0000_0001 > 0 { 1 } else { 0 }) as u16;

        let carry = sum > 0xff;

        if carry {
            self.status = self.status | 0b0000_0001;
        } else {
            self.status = self.status & 0b1111_1110;
        }

        let result = sum as u8;

        if (data ^ result) & (result ^ self.register_a) & 0x80 != 0 {
            self.status = self.status | 0b0100_0000;
        } else {
            self.status = self.status & 0b1011_1111;
        }

        self.register_a = result;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn sub_from_register_a(&mut self, data: u8) {
        self.add_to_register_a(((data as i8).wrapping_neg().wrapping_sub(1)) as u8);
    }

    fn set_register_a(&mut self, value: u8) {
        self.register_a = value;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn and_with_register_a(&mut self, data: u8) {
        self.set_register_a(data & self.register_a);
    }

    fn xor_with_register_a(&mut self, data: u8) {
        self.set_register_a(data ^ self.register_a);
    }

    fn or_with_register_a(&mut self, data: u8) {
        self.set_register_a(data | self.register_a);
    }

    fn sbc(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(&mode);
        let data = self.mem_read(addr);
        if page_cross {
            self.bus.tick(1);
        }
        self.add_to_register_a(((data as i8).wrapping_neg().wrapping_sub(1)) as u8);
    }

    fn adc(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        if page_cross {
            self.bus.tick(1);
        }
        self.add_to_register_a(value);
    }

    fn and(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value & self.register_a;

        if page_cross {
            self.bus.tick(1);
        }

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn aax(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let and = self.register_x & self.register_a;

        self.mem_write(addr, and);
    }

    fn eor(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value ^ self.register_a;

        if page_cross {
            self.bus.tick(1);
        }

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn ora(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value | self.register_a;

        if page_cross {
            self.bus.tick(1);
        }

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn asl_accumulator(&mut self) {
        let value = self.register_a;

        let updated_value = value << 1;
        self.register_a = updated_value;
        let carry = (value & 0b1000_0000) == 0b1000_0000;

        self.update_carry_flag(carry);
        self.update_zero_and_negative_flags(updated_value);
    }

    fn asl(&mut self, mode: &AddressingMode) -> u8 {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        let updated_value = value << 1;
        self.mem_write(addr, updated_value);
        let carry = (value & 0b1000_0000) == 0b1000_0000;

        self.update_carry_flag(carry);
        self.update_zero_and_negative_flags(updated_value);
        updated_value
    }

    fn lsr_accumulator(&mut self) {
        let carry: bool = (self.register_a & 0b0000_0001) == 0b0000_0001;
        let updated_value = self.register_a >> 1;

        self.register_a = updated_value;

        self.update_carry_flag(carry);
        self.update_zero_and_negative_flags(updated_value);
    }

    fn lsr(&mut self, mode: &AddressingMode) -> u8 {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        let updated_value = value >> 1;

        self.mem_write(addr, updated_value);
        let carry = (value & 0b0000_0001) == 0b0000_0001;

        self.update_carry_flag(carry);
        self.update_zero_and_negative_flags(updated_value);

        updated_value
    }

    fn rol_accumulator(&mut self) {
        let value = self.register_a;

        let old_carry = self.is_carry_flag_set();

        let mut updated_value = value << 1;

        if old_carry {
            // Bit 0 is filled with the current value of the carry flag
            updated_value = updated_value.wrapping_add(1);
        }

        self.register_a = updated_value;

        let carry = (value & 0b1000_0000) == 0b1000_0000;
        self.update_carry_flag(carry);

        self.update_zero_and_negative_flags(updated_value);
    }

    fn rol(&mut self, mode: &AddressingMode) -> u8 {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        let old_carry = self.is_carry_flag_set();

        let mut updated_value = value << 1;

        if old_carry {
            // Bit 0 is filled with the current value of the carry flag
            updated_value = updated_value.wrapping_add(1);
        }

        self.mem_write(addr, updated_value);

        let carry = (value & 0b1000_0000) == 0b1000_0000;
        self.update_carry_flag(carry);

        self.update_zero_and_negative_flags(updated_value);

        updated_value
    }

    fn ror_accumulator(&mut self) {
        let value = self.register_a;

        let old_carry = self.is_carry_flag_set();

        let mut updated_value = value >> 1;

        if old_carry {
            // Bit 7 is filled with the current value of the carry flag
            updated_value = updated_value.wrapping_add(128);
        }

        self.register_a = updated_value;

        let carry = (value & 0b0000_0001) == 0b0000_0001;
        self.update_carry_flag(carry);

        self.update_zero_and_negative_flags(updated_value);
    }

    fn ror(&mut self, mode: &AddressingMode) -> u8 {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        let old_carry = self.is_carry_flag_set();

        let mut updated_value = value >> 1;

        if old_carry {
            // Bit 7 is filled with the current value of the carry flag
            updated_value = updated_value.wrapping_add(128);
        }

        self.mem_write(addr, updated_value);

        let carry = (value & 0b0000_0001) == 0b0000_0001;
        self.update_carry_flag(carry);

        self.update_zero_and_negative_flags(updated_value);
        updated_value
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value;

        if page_cross {
            self.bus.tick(1);
        }

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn ldx(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_x = value;

        if page_cross {
            self.bus.tick(1);
        }

        self.update_zero_and_negative_flags(self.register_x);
    }

    fn ldy(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_y = value;

        if page_cross {
            self.bus.tick(1);
        }

        self.update_zero_and_negative_flags(self.register_y);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        self.mem_write(addr, self.register_a);
    }

    fn stx(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        self.mem_write(addr, self.register_x);
    }

    fn sty(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        self.mem_write(addr, self.register_y);
    }
    fn sec(&mut self) {
        self.status = self.status | 0b0000_0001;
    }

    fn sed(&mut self) {
        self.status = self.status | 0b0000_1000;
    }

    fn sei(&mut self) {
        self.status = self.status | 0b0000_0100;
    }

    fn clc(&mut self) {
        self.status = self.status & 0b1111_1110;
    }

    fn cld(&mut self) {
        self.status = self.status & 0b1111_0111;
    }

    fn cli(&mut self) {
        self.status = self.status & 0b1111_1011;
    }

    fn clv(&mut self) {
        self.status = self.status & 0b1011_1111;
    }

    fn tax(&mut self) {
        self.register_x = self.register_a;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn tay(&mut self) {
        self.register_y = self.register_a;
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn txs(&mut self) {
        self.stack_pointer = self.register_x;
    }

    fn tsx(&mut self) {
        self.register_x = self.stack_pointer;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn txa(&mut self) {
        self.register_a = self.register_x;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn tya(&mut self) {
        self.register_a = self.register_y;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn dec(&mut self, mode: &AddressingMode) {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        let value = value.wrapping_sub(1);

        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(value);
    }

    fn dex(&mut self) {
        self.register_x = self.register_x.wrapping_sub(1);
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn dey(&mut self) {
        self.register_y = self.register_y.wrapping_sub(1);
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn inc(&mut self, mode: &AddressingMode) -> u8 {
        let (addr, page_cross) = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        let value = value.wrapping_add(1);

        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(value);

        value
    }

    fn inx(&mut self) {
        self.register_x = self.register_x.wrapping_add(1);
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn iny(&mut self) {
        self.register_y = self.register_y.wrapping_add(1);
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn is_carry_flag_set(&mut self) -> bool {
        (self.status & 0b0000_0001) == 0b0000_0001
    }

    fn update_carry_flag(&mut self, carry: bool) {
        if carry {
            self.status = self.status | 0b0000_0001
        } else {
            self.status = self.status & 0b1111_1110
        }
    }

    fn update_zero_and_negative_flags(&mut self, result: u8) {
        if result == 0 {
            self.status = self.status | 0b0000_0010;
        } else {
            self.status = self.status & 0b1111_1101;
        }

        if result & 0b1000_0000 != 0 {
            self.status = self.status | 0b1000_0000;
        } else {
            self.status = self.status & 0b0111_1111;
        }
    }

    fn stack_pop(&mut self) -> u8 {
        self.stack_pointer = self.stack_pointer.wrapping_add(1);
        self.mem_read((STACK as u16) + self.stack_pointer as u16)
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write((STACK as u16) + self.stack_pointer as u16, data);
        self.stack_pointer = self.stack_pointer.wrapping_sub(1)
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.stack_push(hi);
        self.stack_push(lo);
    }

    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;

        hi << 8 | lo
    }

    fn pla(&mut self) {
        let data = self.stack_pop();
        self.register_a = data;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn plp(&mut self) {
        self.status = self.stack_pop();
        self.status = self.status & 0b1110_1111;
        self.status = self.status | 0b0010_0000;
    }

    fn php(&mut self) {
        self.stack_push(self.status | 0b0011_0000);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cartridge::test;

    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);

        assert_eq!(cpu.register_a, 0x05);
        assert!(cpu.status & 0b0000_0010 == 0b0000_0000);
        assert!(cpu.status & 0b1000_0000 == 0b0000_0000);
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b0000_0010 == 0b0000_0010);
    }

    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 10;
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0x00]);

        assert_eq!(cpu.register_x, 0xFF)
    }

    #[test]
    fn test_5_ops_working_together() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 0xc1)
    }

    #[test]
    fn test_inx() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 2)
    }

    #[test]
    fn test_inx_overflow() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_x = 0xff;
        cpu.load_and_run(vec![0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 1)
    }

    #[test]
    fn test_lda_from_memory() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x10, 0x55);

        cpu.load_and_run(vec![0xa5, 0x10, 0x00]);

        assert_eq!(cpu.register_a, 0x55);
    }

    #[test]
    fn test_ldx_immediate() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xa2, 0x10, 0x00]);

        assert_eq!(cpu.register_x, 0x10);
    }

    #[test]
    fn test_ldx_from_memory() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x10, 0x55);
        cpu.load_and_run(vec![0xa6, 0x10, 0x00]);

        assert_eq!(cpu.register_x, 0x55);
    }

    #[test]
    fn test_ldy_immediate() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xa0, 0x10, 0x00]);

        assert_eq!(cpu.register_y, 0x10);
    }

    #[test]
    fn test_ldy_from_memory() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x10, 0x55);
        cpu.load_and_run(vec![0xa4, 0x10, 0x00]);

        assert_eq!(cpu.register_y, 0x55);
    }

    #[test]
    fn test_adc() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);

        cpu.register_a = 0x04;
        cpu.mem_write(0x11, 0x40);
        cpu.load_and_run(vec![0x65, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x44);
        assert_eq!(cpu.mem_read(0x11), 0x40);
        assert_eq!(cpu.status, DEFAULT_CPU_STATUS);
    }

    #[test]
    fn test_adc_with_overflow() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);

        cpu.register_a = 0xff;
        cpu.mem_write(0x11, 0x02);
        cpu.load_and_run(vec![0x65, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x01);
        assert_eq!(cpu.mem_read(0x11), 0x02);
        assert_eq!(cpu.is_carry_flag_set(), true);
    }

    #[test]
    fn test_adc_with_carry() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);

        cpu.register_a = 0x40;
        cpu.status = 0b0000_0001;
        cpu.mem_write(0x11, 0x02);
        cpu.load_and_run(vec![0x65, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x43);
        assert_eq!(cpu.mem_read(0x11), 0x02);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    #[test]
    fn test_sbc() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);

        cpu.register_a = 0x09;
        cpu.mem_write(0x11, 0x04);
        cpu.load_and_run(vec![0xe5, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x04);
        assert_eq!(cpu.mem_read(0x11), 0x04);
        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0x01);
    }

    #[test]
    fn test_sbc_with_overflow() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);

        cpu.register_a = 0xFD;
        cpu.mem_write(0x11, 0xff);
        cpu.load_and_run(vec![0xe5, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0xFD);
        assert_eq!(cpu.mem_read(0x11), 0xff);
        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b1000_0000);
    }

    #[test]
    fn test_sbc_with_carry() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);

        cpu.register_a = 0x44;
        cpu.status = 0b1000_0000;
        cpu.mem_write(0x11, 0x02);
        cpu.load_and_run(vec![0xe5, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x41);
        assert_eq!(cpu.mem_read(0x11), 0x02);
        assert_eq!(cpu.status, 0b0000_0001);
    }

    #[test]
    fn test_and_ff() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);

        cpu.register_a = 0xFF;
        cpu.mem_write(0x11, 0xFF);
        cpu.load_and_run(vec![0x25, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0xFF);
    }

    #[test]
    fn test_and2() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0xFF;
        cpu.mem_write(0x11, 0x2D);
        cpu.load_and_run(vec![0x25, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x2D);
    }

    #[test]
    fn test_asl() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0b0101_0101);
        cpu.load_and_run(vec![0x06, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b1010_1010);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    #[test]
    fn test_asl_overflow() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x06, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0100);
        assert_eq!(cpu.is_carry_flag_set(), true);
    }

    #[test]
    fn test_lsr() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x46, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0101);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    #[test]
    fn test_lsr_overflow() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0b0101_0101);
        cpu.load_and_run(vec![0x46, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0010_1010);
        assert_eq!(cpu.is_carry_flag_set(), true);
    }

    #[test]
    fn test_sec() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0x38, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0001);
    }

    #[test]
    fn test_sed() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0xF8, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_1000);
    }

    #[test]
    fn test_sei() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.load_and_run(vec![0x78, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0100);
    }

    #[test]
    fn test_clc() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0x18, 0x00]);

        assert_eq!(cpu.status, 0b1111_1110);
    }

    #[test]
    fn test_cld() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0xD8, 0x00]);

        assert_eq!(cpu.status, 0b1111_0111);
    }

    #[test]
    fn test_cli() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0x58, 0x00]);

        assert_eq!(cpu.status, 0b1111_1011);
    }

    #[test]
    fn test_clv() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0xB8, 0x00]);

        assert_eq!(cpu.status, 0b1011_1111);
    }

    #[test]
    fn test_ora_immediate() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0b1111_0000;
        cpu.load_and_run(vec![0x09, 0b1010_1010, 0x00]);

        assert_eq!(cpu.register_a, 0b1111_1010);
    }

    #[test]
    fn test_ora_memory() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0b1111_0000;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x05, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0b1111_1010);
    }

    #[test]
    fn test_eor_immediate() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0b1111_0000;
        cpu.load_and_run(vec![0x49, 0b1010_1010, 0x00]);

        assert_eq!(cpu.register_a, 0b0101_1010);
    }

    #[test]
    fn test_eor_memory() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0b1111_0000;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x45, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0b0101_1010);
    }

    #[test]
    fn test_inc() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0xE1);
        cpu.load_and_run(vec![0xE6, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xE2);
    }

    #[test]
    fn test_iny() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_y = 0xE1;
        cpu.load_and_run(vec![0xC8, 0x00]);

        assert_eq!(cpu.register_y, 0xE2);
    }

    #[test]
    fn test_dec() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0xE1);
        cpu.load_and_run(vec![0xC6, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xE0);
    }

    #[test]
    fn test_dex() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_x = 0xE1;
        cpu.load_and_run(vec![0xCA, 0x00]);

        assert_eq!(cpu.register_x, 0xE0);
    }

    #[test]
    fn test_dey() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_y = 0xE1;
        cpu.load_and_run(vec![0x88, 0x00]);

        assert_eq!(cpu.register_y, 0xE0);
    }

    #[test]
    fn test_rol() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b0000_0000;
        cpu.mem_write(0x11, 0b0101_0101);
        cpu.load_and_run(vec![0x26, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b1010_1010);
        assert_eq!(cpu.status, 0b1000_0000);
    }

    #[test]
    fn test_rol_with_carry() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b0000_0001;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x26, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0101);
        assert_eq!(cpu.status, 0b0000_0001);
    }

    #[test]
    fn test_ror() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b0000_0000;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x66, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0101);
        assert_eq!(cpu.status, 0b0000_0000);
    }

    #[test]
    fn test_ror_with_carry() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b0000_0001;
        cpu.mem_write(0x11, 0b1010_1011);
        cpu.load_and_run(vec![0x66, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b1101_0101);
        assert_eq!(cpu.status, 0b1000_0001);
    }

    #[test]
    fn test_sta() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0xBA;
        cpu.load_and_run(vec![0x85, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xBA);
    }

    #[test]
    fn test_stx() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_x = 0xBA;
        cpu.load_and_run(vec![0x86, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xBA);
    }

    #[test]
    fn test_sty() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_y = 0xBA;
        cpu.load_and_run(vec![0x84, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xBA);
    }

    #[test]
    fn test_tax() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0xAB;
        cpu.load_and_run(vec![0xaa, 0x00]);

        assert_eq!(cpu.register_x, 0xAB)
    }

    #[test]
    fn test_tay() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0xAB;
        cpu.load_and_run(vec![0xa8, 0x00]);

        assert_eq!(cpu.register_y, 0xAB)
    }

    #[test]
    fn test_txa() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_x = 0xAB;
        cpu.load_and_run(vec![0x8a, 0x00]);

        assert_eq!(cpu.register_a, 0xAB)
    }

    #[test]
    fn test_tya() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_y = 0xAB;
        cpu.load_and_run(vec![0x98, 0x00]);

        assert_eq!(cpu.register_a, 0xAB)
    }

    #[test]
    fn test_cmp_immediate_zero() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        // cpu.mem_write(0x11, 0xAA);
        cpu.register_a = 0xAA;
        cpu.load_and_run(vec![0xC9, 0xAA, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0011)
    }

    #[test]
    fn test_cmp_memory_negative() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0xAB);
        cpu.register_a = 0xAA;
        cpu.load_and_run(vec![0xC5, 0x11, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b1000_0000)
    }

    #[test]
    fn test_cmp_immediate_positive() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0xAA;
        cpu.load_and_run(vec![0xC9, 0xA0, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0001)
    }

    #[test]
    fn test_cpx_immediate_zero() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_x = 0xAA;
        cpu.load_and_run(vec![0xE0, 0xAA, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0011)
    }

    #[test]
    fn test_cpx_memory_negative() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0xAB);
        cpu.register_x = 0xAA;
        cpu.load_and_run(vec![0xE4, 0x11, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b1000_0000)
    }

    #[test]
    fn test_cpx_immediate_positive() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_x = 0xAA;
        cpu.load_and_run(vec![0xE0, 0xA0, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0001)
    }

    #[test]
    fn test_cpy_immediate_zero() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_y = 0xAA;
        cpu.load_and_run(vec![0xC0, 0xAA, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0011)
    }

    #[test]
    fn test_cpy_memory_negative() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.mem_write(0x11, 0xAB);
        cpu.register_y = 0xAA;
        cpu.load_and_run(vec![0xC4, 0x11, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b1000_0000)
    }

    #[test]
    fn test_cpy_immediate_positive() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_y = 0xAA;
        cpu.load_and_run(vec![0xC0, 0xA0, 0x00]);

        assert_eq!(cpu.status, DEFAULT_CPU_STATUS | 0b0000_0001)
    }

    #[test]
    fn test_asl_accumulator() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0b0101_0101;
        cpu.load_and_run(vec![0x0A, 0x00]);

        assert_eq!(cpu.register_a, 0b1010_1010);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    #[test]
    fn test_lsr_accumulator() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_a = 0b1010_1010;
        cpu.load_and_run(vec![0x4A, 0x00]);

        assert_eq!(cpu.register_a, 0b0101_0101);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    #[test]
    fn test_rol_accumulator() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b0000_0000;
        cpu.register_a = 0b0101_0101;
        cpu.load_and_run(vec![0x2A, 0x00]);

        assert_eq!(cpu.register_a, 0b1010_1010);
        assert_eq!(cpu.status, 0b1000_0000);
    }

    #[test]
    fn test_ror_accumulator() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.status = 0b0000_0000;
        cpu.register_a = 0b1010_1010;
        cpu.load_and_run(vec![0x6A, 0x00]);

        assert_eq!(cpu.register_a, 0b0101_0101);
        assert_eq!(cpu.status, 0b0000_0000);
    }

    #[test]
    fn test_tsx() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.stack_pointer = 0x10;
        cpu.load_and_run(vec![0xBA, 0x00]);

        assert_eq!(cpu.register_x, 0x10);
    }

    #[test]
    fn test_txs() {
        let bus = Bus::new(test::test_rom());
        let mut cpu = CPU::new(bus);
        cpu.register_x = 0x10;
        cpu.load_and_run(vec![0x9A, 0x00]);

        assert_eq!(cpu.stack_pointer, 0x10);
    }

    // #[test]
    // fn test_bcc() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.load_and_run(vec![0x90, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_bcs() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.status = 0b0000_0001;
    //     cpu.load_and_run(vec![0xB0, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_beq() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.status = 0b0000_0010;
    //     cpu.load_and_run(vec![0xF0, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_bmi() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.status = 0b1000_0000;
    //     cpu.load_and_run(vec![0x30, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_bne() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.load_and_run(vec![0xD0, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_bpl() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.load_and_run(vec![0x10, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_bvc() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.load_and_run(vec![0x50, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_bvs() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.status = 0b0100_0000;
    //     cpu.load_and_run(vec![0x70, 0x10, 0x00]);

    //     assert_eq!(cpu.program_counter, 0x8013);
    // }

    // #[test]
    // fn test_bit() {
    //             let bus = Bus::new(test::test_rom());
    // let mut cpu = CPU::new(bus);
    //     cpu.register_a = 0b1010_1010;
    //     cpu.mem_write(0x11, 0b0101_0101);
    //     cpu.load_and_run(vec![0x24, 0x11, 0x00]);

    //     assert_eq!(cpu.status, 0b0100_0010);
    // }
}
