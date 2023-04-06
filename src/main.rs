use std::fmt::Binary;
use std::io::{BufRead, BufReader};
use std::cmp::max;
extern crate BytecodeAnalyzer;
use BytecodeAnalyzer::*;
const BATCH_SIZE: usize = 1000;
const NUM_ROUNDS: usize = 5;
use std::path::Path;



fn decompile(file: &Path, filetype: BinaryFileType) -> Result<(), MyError>{
    
    if let BinaryFileType::PE = filetype {
        let decompiled = BytecodeAnalyzer::disassemble_pe_file(file);
        decompiled.unwrap_or_else(|err| {
            eprintln!("An error occured: {}", err);
        });
    }
    if let BinaryFileType::ELF = filetype {
        let decompiled = BytecodeAnalyzer::disassemble_elf_file(file);
        decompiled.unwrap_or_else(|err| {
            eprintln!("An error occured: {}", err);
        });
    }
    if let BinaryFileType::MachO = filetype {
        let decompiled = BytecodeAnalyzer::disassemble_macho_file(file);
        decompiled.unwrap_or_else(|err| {
            eprintln!("An error occured: {}", err);
        });
    }

    Ok(())
}
fn main() {
    
    let filename = Path::new("main.exe");
    println!("{:?}", filename);
    let filetype = BytecodeAnalyzer::get_binary_file_type(filename);
    match filetype {
        Ok(file_type) => {
            println!("File Type is {:?}", file_type);
            decompile(filename,file_type);
        }
        Err(err) => {
            eprintln!("An error occured: {}", err);
        }
    }
    let test = BytecodeAnalyzer::print_pe32_headerinfo(filename);
    test.unwrap_or_else(|err| {
        eprintln!("An error occured: {}", err);
    })




}