use crate::opcodes;
use std::collections::HashMap;

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Accumulator,
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

#[derive(Debug)]
pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub status: u8,
    pub program_counter: u16,
    memory: [u8; 0xffff],
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            register_y: 0,
            status: 0,
            program_counter: 0,
            memory: [0; 0xffff],
        }
    }

    fn mem_read(&self, addr: u16) -> u8 {
        self.memory[addr as usize]
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.memory[addr as usize] = data;
    }

    fn mem_read_u16(&self, pos: u16) -> u16 {
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

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = 0;

        self.program_counter = self.mem_read_u16(0xFFFC);
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.memory[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xFFFC, 0x8000);
    }

    pub fn load_reset_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run()
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.program_counter = self.mem_read_u16(0xFFFC);
        self.run()
    }

    pub fn run(&mut self) {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
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
                0x0A | 0x06 | 0x16 | 0x0E | 0x1E => self.asl(&opscode.mode),
                /* CLC */
                0x18 => self.clc(),
                /* CLD */
                0xD8 => self.cld(),
                /* CLI */
                0x58 => self.cli(),
                /* CLV */
                0xB8 => self.clv(),
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
                0x4A | 0x46 | 0x56 | 0x4E | 0x5E => {
                    self.lsr(&opscode.mode);
                }
                /* NOP */
                0xEA => {}
                /* ORA */
                0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 => self.ora(&opscode.mode),
                /* ROL */
                0x2A | 0x26 | 0x36 | 0x2E | 0x3E => {
                    self.rol(&opscode.mode);
                }
                /* ROR */
                0x6A | 0x66 | 0x76 | 0x6E | 0x7E => {
                    self.ror(&opscode.mode);
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
                /* TXA */
                0x8A => self.txa(),
                /* TYA */
                0x98 => self.tya(),
                0x00 => {
                    return;
                }
                _ => todo!(),
            }

            if program_counter_state == self.program_counter {
                self.program_counter += (opscode.bytes - 1) as u16;
            }
        }
    }

    // TODO: Fix accumulator
    fn get_operand_address(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Accumulator => todo!("how accumulator works?"),

            AddressingMode::Immediate => self.program_counter,

            AddressingMode::ZeroPage => self.mem_read(self.program_counter) as u16,

            AddressingMode::Absolute => self.mem_read_u16(self.program_counter),

            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_x) as u16;
                addr
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_y) as u16;
                addr
            }

            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_x as u16);
                addr
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_y as u16);
                addr
            }

            AddressingMode::Indirect_X => {
                let base = self.mem_read(self.program_counter);

                let ptr: u8 = (base as u8).wrapping_add(self.register_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(self.program_counter);

                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.register_y as u16);
                deref
            }

            AddressingMode::NoneAddressing => {
                panic!("mode {:?} is not supported", mode);
            }
        }
    }

    fn adc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        // nightly only
        // let (updated_value, carry) = self
        //     .register_a
        //     .carrying_add(value, self.is_carry_flag_set(self.status));

        let (value, carry) = self.register_a.overflowing_add(value);
        let mut updated_value = value;
        let mut updated_carry = carry;
        if self.is_carry_flag_set() {
            (updated_value, updated_carry) = value.overflowing_add(1);
            updated_carry = updated_carry | carry
        }

        self.mem_write(addr, updated_value);

        self.update_carry_flag(updated_carry);
        self.update_zero_and_negative_flags(updated_value);
    }

    fn sbc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        let (value, carry) = self.register_a.overflowing_sub(value);
        // let mut updated_value = value;
        // let mut updated_carry = carry;

        // if !self.is_carry_flag_set() {
        //     (updated_value, updated_carry) = value.overflowing_sub(1);
        //     updated_carry = updated_carry | carry
        // }

        self.mem_write(addr, value);

        self.update_carry_flag(carry);
        self.update_zero_and_negative_flags(value);
    }

    fn and(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value & self.register_a;

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn eor(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value ^ self.register_a;

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn ora(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value | self.register_a;

        self.update_zero_and_negative_flags(self.register_a);
    }

    // TODO: fix AddressingMode::Accumulator
    fn asl(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        let updated_value = value << 1;
        self.mem_write(addr, updated_value);
        let carry = (value & 0b1000_0000) == 0b1000_0000;

        self.update_carry_flag(carry);
        self.update_zero_and_negative_flags(updated_value);
    }

    // TODO: fix AddressingMode::Accumulator
    fn lsr(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        let updated_value = value >> 1;

        self.mem_write(addr, updated_value);
        let carry = (value & 0b0000_0001) == 0b0000_0001;

        self.update_carry_flag(carry);
        self.update_zero_and_negative_flags(updated_value);
    }

    fn rol(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
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
    }

    fn ror(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
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
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value;

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn ldx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_x = value;

        self.update_zero_and_negative_flags(self.register_x);
    }

    fn ldy(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_y = value;

        self.update_zero_and_negative_flags(self.register_y);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_a);
    }

    fn stx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_x);
    }

    fn sty(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
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

    fn txa(&mut self) {
        self.register_a = self.register_x;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn tya(&mut self) {
        self.register_a = self.register_y;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn dec(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.mem_write(addr, value.wrapping_sub(1));
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

    fn inc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.mem_write(addr, value.wrapping_add(1));
        self.update_zero_and_negative_flags(value);
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);

        assert_eq!(cpu.register_a, 0x05);
        assert!(cpu.status & 0b0000_0010 == 0b0000_0000);
        assert!(cpu.status & 0b1000_0000 == 0b0000_0000);
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b0000_0010 == 0b0000_0010);
    }

    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let mut cpu = CPU::new();
        cpu.register_a = 10;
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0x00]);

        assert_eq!(cpu.register_x, 0xFF)
    }

    #[test]
    fn test_5_ops_working_together() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 0xc1)
    }

    #[test]
    fn test_inx() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 2)
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.register_x = 0xff;
        cpu.load_and_run(vec![0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 1)
    }

    #[test]
    fn test_lda_from_memory() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x10, 0x55);

        cpu.load_and_run(vec![0xa5, 0x10, 0x00]);

        assert_eq!(cpu.register_a, 0x55);
    }

    #[test]
    fn test_ldx_immediate() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa2, 0x10, 0x00]);

        assert_eq!(cpu.register_x, 0x10);
    }

    #[test]
    fn test_ldx_from_memory() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x10, 0x55);
        cpu.load_and_run(vec![0xa6, 0x10, 0x00]);

        assert_eq!(cpu.register_x, 0x55);
    }

    #[test]
    fn test_ldy_immediate() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa0, 0x10, 0x00]);

        assert_eq!(cpu.register_y, 0x10);
    }

    #[test]
    fn test_ldy_from_memory() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x10, 0x55);
        cpu.load_and_run(vec![0xa4, 0x10, 0x00]);

        assert_eq!(cpu.register_y, 0x55);
    }

    #[test]
    fn test_adc() {
        let mut cpu = CPU::new();

        cpu.register_a = 0x04;
        cpu.mem_write(0x11, 0x40);
        cpu.load_and_run(vec![0x65, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x04);
        assert_eq!(cpu.mem_read(0x11), 0x44);
        assert_eq!(cpu.status, 0x00);
    }

    #[test]
    fn test_adc_with_overflow() {
        let mut cpu = CPU::new();

        cpu.register_a = 0xff;
        cpu.mem_write(0x11, 0x02);
        cpu.load_and_run(vec![0x65, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0xff);
        assert_eq!(cpu.mem_read(0x11), 0x01);
        assert_eq!(cpu.is_carry_flag_set(), true);
    }

    #[test]
    fn test_adc_with_carry() {
        let mut cpu = CPU::new();

        cpu.register_a = 0x40;
        cpu.status = 0b0000_0001;
        cpu.mem_write(0x11, 0x02);
        cpu.load_and_run(vec![0x65, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x40);
        assert_eq!(cpu.mem_read(0x11), 0x43);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    #[test]
    fn test_sbc() {
        let mut cpu = CPU::new();

        cpu.register_a = 0x09;
        cpu.mem_write(0x11, 0x04);
        cpu.load_and_run(vec![0xe5, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x09);
        assert_eq!(cpu.mem_read(0x11), 0x05);
        assert_eq!(cpu.status, 0x00);
    }

    // TODO: fix overflow in SBC
    // #[test]
    // fn test_sbc_with_overflow() {
    //     let mut cpu = CPU::new();

    //     cpu.register_a = 0xff;
    //     cpu.mem_write(0x11, 0x02);
    //     cpu.load_and_run(vec![0xe5, 0x11, 0x00]);

    //     assert_eq!(cpu.register_a, 0xff);
    //     assert_eq!(cpu.mem_read(0x11), 0x01);
    //     assert_eq!(cpu.status, 0b1000_0000);
    // }

    // #[test]
    // fn test_sbc_with_carry() {
    //     let mut cpu = CPU::new();

    //     cpu.register_a = 0x40;
    //     cpu.status = 0b1000_0000;
    //     cpu.mem_write(0x11, 0x02);
    //     cpu.load_and_run(vec![0xe5, 0x11, 0x00]);

    //     assert_eq!(cpu.register_a, 0x40);
    //     assert_eq!(cpu.mem_read(0x11), 0x43);
    //     assert_eq!(cpu.status, 0b0000_0000);
    // }

    #[test]
    fn test_and_ff() {
        let mut cpu = CPU::new();

        cpu.register_a = 0xFF;
        cpu.mem_write(0x11, 0xFF);
        cpu.load_and_run(vec![0x25, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0xFF);
    }

    #[test]
    fn test_and2() {
        let mut cpu = CPU::new();
        cpu.register_a = 0xFF;
        cpu.mem_write(0x11, 0x2D);
        cpu.load_and_run(vec![0x25, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0x2D);
    }

    #[test]
    fn test_asl() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x11, 0b0101_0101);
        cpu.load_and_run(vec![0x06, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b1010_1010);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    #[test]
    fn test_asl_overflow() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x06, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0100);
        assert_eq!(cpu.is_carry_flag_set(), true);
    }

    #[test]
    fn test_lsr() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x46, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0101);
        assert_eq!(cpu.is_carry_flag_set(), false);
    }

    // #[test]
    // fn test_lsr_overflow() {
    //     let mut cpu = CPU::new();
    //     cpu.mem_write(0x11, 0b0101_0101);
    //     cpu.load_and_run(vec![0x46, 0x11, 0x00]);

    //     assert_eq!(cpu.mem_read(0x11), 0b0010_1010);
    //     assert_eq!(cpu.is_carry_flag_set(), true);
    // }

    #[test]
    fn test_sec() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0x38, 0x00]);

        assert_eq!(cpu.status, 0b0000_0001);
    }

    #[test]
    fn test_sed() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xF8, 0x00]);

        assert_eq!(cpu.status, 0b0000_1000);
    }

    #[test]
    fn test_sei() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0x78, 0x00]);

        assert_eq!(cpu.status, 0b0000_0100);
    }

    #[test]
    fn test_clc() {
        let mut cpu = CPU::new();
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0x18, 0x00]);

        assert_eq!(cpu.status, 0b1111_1110);
    }

    #[test]
    fn test_cld() {
        let mut cpu = CPU::new();
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0xD8, 0x00]);

        assert_eq!(cpu.status, 0b1111_0111);
    }

    #[test]
    fn test_cli() {
        let mut cpu = CPU::new();
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0x58, 0x00]);

        assert_eq!(cpu.status, 0b1111_1011);
    }

    #[test]
    fn test_clv() {
        let mut cpu = CPU::new();
        cpu.status = 0b1111_1111;
        cpu.load_and_run(vec![0xB8, 0x00]);

        assert_eq!(cpu.status, 0b1011_1111);
    }

    #[test]
    fn test_ora_immediate() {
        let mut cpu = CPU::new();
        cpu.register_a = 0b1111_0000;
        cpu.load_and_run(vec![0x09, 0b1010_1010, 0x00]);

        assert_eq!(cpu.register_a, 0b1111_1010);
    }

    #[test]
    fn test_ora_memory() {
        let mut cpu = CPU::new();
        cpu.register_a = 0b1111_0000;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x05, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0b1111_1010);
    }

    #[test]
    fn test_eor_immediate() {
        let mut cpu = CPU::new();
        cpu.register_a = 0b1111_0000;
        cpu.load_and_run(vec![0x49, 0b1010_1010, 0x00]);

        assert_eq!(cpu.register_a, 0b0101_1010);
    }

    #[test]
    fn test_eor_memory() {
        let mut cpu = CPU::new();
        cpu.register_a = 0b1111_0000;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x45, 0x11, 0x00]);

        assert_eq!(cpu.register_a, 0b0101_1010);
    }

    #[test]
    fn test_inc() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x11, 0xE1);
        cpu.load_and_run(vec![0xE6, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xE2);
    }

    #[test]
    fn test_iny() {
        let mut cpu = CPU::new();
        cpu.register_y = 0xE1;
        cpu.load_and_run(vec![0xC8, 0x00]);

        assert_eq!(cpu.register_y, 0xE2);
    }

    #[test]
    fn test_dec() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x11, 0xE1);
        cpu.load_and_run(vec![0xC6, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xE0);
    }

    #[test]
    fn test_dex() {
        let mut cpu = CPU::new();
        cpu.register_x = 0xE1;
        cpu.load_and_run(vec![0xCA, 0x00]);

        assert_eq!(cpu.register_x, 0xE0);
    }

    #[test]
    fn test_dey() {
        let mut cpu = CPU::new();
        cpu.register_y = 0xE1;
        cpu.load_and_run(vec![0x88, 0x00]);

        assert_eq!(cpu.register_y, 0xE0);
    }

    #[test]
    fn test_rol() {
        let mut cpu = CPU::new();
        cpu.status = 0b0000_0000;
        cpu.mem_write(0x11, 0b0101_0101);
        cpu.load_and_run(vec![0x26, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b1010_1010);
        assert_eq!(cpu.status, 0b1000_0000);
    }

    #[test]
    fn test_rol_with_carry() {
        let mut cpu = CPU::new();
        cpu.status = 0b0000_0001;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x26, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0101);
        assert_eq!(cpu.status, 0b0000_0001);
    }

    #[test]
    fn test_ror() {
        let mut cpu = CPU::new();
        cpu.status = 0b0000_0000;
        cpu.mem_write(0x11, 0b1010_1010);
        cpu.load_and_run(vec![0x66, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b0101_0101);
        assert_eq!(cpu.status, 0b0000_0000);
    }

    #[test]
    fn test_ror_with_carry() {
        let mut cpu = CPU::new();
        cpu.status = 0b0000_0001;
        cpu.mem_write(0x11, 0b1010_1011);
        cpu.load_and_run(vec![0x66, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0b1101_0101);
        assert_eq!(cpu.status, 0b1000_0001);
    }

    #[test]
    fn test_sta() {
        let mut cpu = CPU::new();
        cpu.register_a = 0xBA;
        cpu.load_and_run(vec![0x85, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xBA);
    }

    #[test]
    fn test_stx() {
        let mut cpu = CPU::new();
        cpu.register_x = 0xBA;
        cpu.load_and_run(vec![0x86, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xBA);
    }

    #[test]
    fn test_sty() {
        let mut cpu = CPU::new();
        cpu.register_y = 0xBA;
        cpu.load_and_run(vec![0x84, 0x11, 0x00]);

        assert_eq!(cpu.mem_read(0x11), 0xBA);
    }

    #[test]
    fn test_tax() {
        let mut cpu = CPU::new();
        cpu.register_a = 0xAB;
        cpu.load_and_run(vec![0xaa, 0x00]);

        assert_eq!(cpu.register_x, 0xAB)
    }

    #[test]
    fn test_tay() {
        let mut cpu = CPU::new();
        cpu.register_a = 0xAB;
        cpu.load_and_run(vec![0xa8, 0x00]);

        assert_eq!(cpu.register_y, 0xAB)
    }

    #[test]
    fn test_txa() {
        let mut cpu = CPU::new();
        cpu.register_x = 0xAB;
        cpu.load_and_run(vec![0x8a, 0x00]);

        assert_eq!(cpu.register_a, 0xAB)
    }

    #[test]
    fn test_tya() {
        let mut cpu = CPU::new();
        cpu.register_y = 0xAB;
        cpu.load_and_run(vec![0x98, 0x00]);

        assert_eq!(cpu.register_a, 0xAB)
    }
}
