use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::error::Error;
use std::io::{Seek, SeekFrom};
use capstone::Error as CsError;
extern crate capstone;
extern crate goblin;
use capstone::arch::{self};
use capstone::prelude::*;
use goblin::{Object};
use goblin::error::Error as ObjectError;
use goblin::pe::*;

//Error Handling enum MyError
pub enum MyError {
    IoError(std::io::Error),
    CsError(CsError),
}

//From trait for MyError converting std::io::Error into MyError

impl From<std::io::Error> for MyError {
    fn from(err: std::io::Error) -> MyError {
        MyError::IoError(err)
    }
}
//Debug for MyError Formats {:?} for error[E0277]
impl std::fmt::Debug for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
//Debug for MyError Displays {:?} for error [E0277]
impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // implement formatting for MyError here
        write!(f, "MyError: {}", self)
    }
}
//Debug for CsError converting  CsError into Capstone::error

impl From<CsError> for MyError {
    fn from(err: CsError) -> Self {
        MyError::CsError(err)
    }
}
#[derive(Debug)]
pub enum BinaryFileType {
    PE,
    ELF,
    MachO,
}

pub fn print_pe32_headerinfo(filepath: &Path) -> Result<(), ObjectError> {
    let mut file = File::open(filepath);
    let mut file_ref = file.as_mut().unwrap();
    file_ref.seek(SeekFrom::Start(0))?;
    let mut buffer = Vec::new();
    file_ref.read_to_end(&mut buffer)?;

    let pe = goblin::Object::parse(&mut buffer)?;

    let file_header = goblin::pe::Coff::parse(&mut buffer)?;

    println!("{:?}", file_header);
    Ok(())

}

pub fn get_binary_file_type(file_path: &Path) -> Result<BinaryFileType, ObjectError> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let object = Object::parse(&buffer)?;
    match object {
        Object::PE(_) => Ok(BinaryFileType::PE),
        Object::Elf(_) => Ok(BinaryFileType::ELF),
        Object::Mach(_) => Ok(BinaryFileType::MachO),
        _ => Err(ObjectError::Malformed("Unknown binary file type".to_owned())),
    }
}

pub fn disassemble_pe_file(file_path: &Path) -> Result<(), MyError> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode32)
        .build()
        .unwrap();

    let insns = cs.disasm_all(&buffer, 0x1000)?;
    for insn in insns.iter() {
        println!("{}", insn);
    }

    Ok(())
}

pub fn disassemble_elf_file(file_path: &Path) -> Result<(), MyError> {
    let mut file = File::open(file_path);
    let mut buffer = Vec::new();
    file?.read_to_end(&mut buffer)?;

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .build()
        .unwrap();

    let insns = cs.disasm_all(&buffer, 0x400)?;
    for insn in insns.iter() {
        println!("{}", insn);
    }

    Ok(())
}

pub fn disassemble_macho_file(file_path: &Path) -> Result<(), MyError> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .build()
        .unwrap();

    let insns = cs.disasm_all(&buffer, 0x1000)?;
    for insn in insns.iter() {
        println!("{}", insn);
    }
    log::debug!("Successfully parsed Mach-O Binary");
    Ok(())
}

pub fn main() {
    env_logger::init();
    let file_path = Path::new("path/to/binary/file");

    match get_binary_file_type(&file_path) {
        Ok(BinaryFileType::PE) => {
            println!("This is a PE file.");
            disassemble_pe_file(&file_path).unwrap();
        }
        Ok(BinaryFileType::ELF) => {
            println!("This is an ELF file.");
            disassemble_elf_file(&file_path).unwrap();
        }
        Ok(BinaryFileType::MachO) => {
            println!("This is a Mach-O file.");
            disassemble_macho_file(&file_path).unwrap();
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}