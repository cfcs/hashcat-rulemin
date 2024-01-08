#![no_main]

use libfuzzer_sys::fuzz_target;
use rulelib::{ Inst, minimize_rule, evaluate_inst, parse_rule };

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 { return; }
    let pw_len : usize = (data[0] & 31).into();
    if (data[0] & !31) != 0 {
        return;
    }
    if data.len() <= pw_len {
        return;
    }
    let (pw, raw_rule) = data.split_at(pw_len);
    match std::str::from_utf8(raw_rule) {
        Ok(input) => {
            match parse_rule(input) {
                Err(_) => {}
                Ok(instructions) => {
                    let mut min_inst = Vec::new();
                    minimize_rule(&instructions, &mut min_inst);
                    let mut mangled_min : Vec<u8> = pw.to_vec();
                    for inst in min_inst.iter() {
                        evaluate_inst(*inst, &mut mangled_min);
                    }
                    if min_inst != instructions {
                        let mut mangled : Vec<u8> = pw.to_vec();
                        for inst in instructions.iter() {
                            evaluate_inst(*inst, &mut mangled);
                        }
                        assert_eq!(
                            mangled_min, mangled,
                            "min={:?}, inst={:?}",
                            min_inst, instructions);
                    }
                }
            }
        }
        Err(_) => {}
    }
});
