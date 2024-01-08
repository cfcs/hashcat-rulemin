#![forbid(unsafe_code)]
/*
 * Parser for a subset of the rules detailed here:
 * https://hashcat.net/wiki/doku.php?id=rule_based_attack
 */

/*
 * Note that some of these instructions have more than
 * one representation in the textual language.
 */
#[derive(Debug,PartialEq,Copy,Clone)]
pub enum Inst {
    Noop,
    Lowercase,
    Uppercase,
    Reverse,
    RotateLeft,
    RotateRight,
    DeleteLastCharacter,
    Extract(u8,u8), // Extract(N,M) delete everything not in range [N:M].
    // M is allowed to overshoot.
    Omit(u8,u8), // Omit(N,M) delete M characters starting at pos N
    Swap(u8,u8), // Swap(N,M) character at position N with character at position M
    // NB: Swap is a no-op if N or M >= pw.len()
      /* 'k' is a special case. note that swapping is commutative. */
    SwapBack, //  Swap last two characters
    Append(u8), // add char at the back
    Insert{off: u8, ch: u8}, // insert ch at offset off
    Overwrite{off: u8, ch: u8}, // overwrite ch at off
    Purge(u8), // Purge(ch): delete all ch - '@x' Purge(b'x') deletes all 'x'
    Replace(u8,u8), // Replace(S,R) replaces all S with R 'sSR'
}

impl ToString for Inst {
    fn to_string(&self) -> String {
        use crate::Inst::*;
        // TODO need to output proper escaping here
        // see parse_inst0, parse_inst1, parse_inst1 etc
        match self {
            Noop        => {String::from(":")}
            Lowercase   => {String::from("l")}
            Uppercase   => {String::from("u")}
            Reverse     => {String::from("r")}
            RotateLeft  => {String::from("{")}
            RotateRight => {String::from("}")}
            DeleteLastCharacter => {String::from("]")}
            Extract(n,m) => {
                format!("x{}{}", unparse_offset(*n), unparse_offset(*m)) }
            Omit(0,1)  => { String::from("[") }
            Omit(n,m)  => {
                format!("O{}{}", unparse_offset(*n), unparse_offset(*m)) }
            Swap(0,1)  => { String::from("k") }
            Swap(n,m)  => {
                format!("*{}{}", unparse_offset(*n), unparse_offset(*m)) }
            SwapBack   => {String::from("K")}
            Append(ch) => { format!("${}", *ch as char) }
            Insert{off,ch}    => {
                format!("i{}{}", unparse_offset(*off), *ch as char) }
            Overwrite{off,ch} => {
                format!("o{}{}", unparse_offset(*off), *ch as char) }
            Purge(ch) => {format!("@{}", *ch as char)}
            Replace(ch_s,ch_r) => {
                format!("s{}{}", *ch_s as char, *ch_r as char)}
        }
    }
}

/*
 * Recursively attempt to collapse a vector of instruction to a smaller
 * (but equivalent) vector.
 */
pub fn minimize_rule(input: &Vec<Inst>, output: &mut Vec<Inst>) {
    use crate::Inst::*;

    output.truncate(0);
    let workvec : &mut Vec<Inst> = &mut input.clone();

    loop {
        let mut skipping = None;
        for (idx, &e) in workvec.iter().enumerate() {
            if let Some(skip_idx) = skipping {
                if idx <= skip_idx { continue; }
            }
            /* All optimizations below must set skipping=Some(_) to
             * trigger a follow-up recursive pass over (output) looking
             * for new optimization opportunities
             * (if a Noop was removed for example):
             */
            match (e, workvec.get(idx+1).copied()) {
                (Noop, _) => { skipping=Some(idx) }
                (Omit(_,0), _) => { skipping=Some(idx) }
                (Swap(a1,a2),_ ) if a1 == a2 => { skipping=Some(idx) }
                /* Reversing twice is a no-op: */
                (Reverse, Some(Reverse)) => { skipping = Some(idx+1) }
                /* Swapping twice is a no-op: */
                (SwapBack, Some(SwapBack)) => { skipping = Some(idx+1) }
                (Swap(a1,a2), Some(Swap(b1,b2))) if (
                    std::cmp::min(a1,a2) == std::cmp::min(b1,b2)
                        && std::cmp::max(a1,a2) == std::cmp::max(b1,b2)
                ) => { skipping = Some(idx+1) }
                /* Append, RotateRight, Omit(0,1) is noop */
                /* Append(Z), RotateRight => Insert(0,Z) */
                (Append(ch), Some(RotateRight)) => {
                    skipping = Some(idx+1);
                    output.push(Insert{off:0,ch});
                }
                /* conversely ^a{ is $a:*/
                (Insert{off:0,ch}, Some(RotateLeft)) => {
                    skipping = Some(idx+1);
                    output.push(Append(ch));
                }
                /* overwriting something just inserted, we turn it into Insert: */
                (Insert{off:ioff,ch:_}, Some(Overwrite{off:ooff,ch})) if ioff == ooff => {
                    skipping = Some(idx+1);
                    output.push(Insert{off:ioff, ch});
                }
                /* $a ] is a no-op: */
                (Append(_), Some(DeleteLastCharacter)) => {
                    skipping = Some(idx+1)
                }
                /* Adding a character and then purging it makes the Append
                 * a no-op (but we should retain the Purge). */
                (Append(a_ch), Some(Purge(p_ch))) if (a_ch == p_ch) => {
                    skipping = Some(idx)
                }
                /* Same for Insert{ch}, Purge(ch) */
                (Insert{ch: a_ch, ..}, Some(Purge(p_ch))) if (a_ch == p_ch) => {
                    skipping = Some(idx)
                }
                /* Overwrite(ch),Purge(ch) can be simplifed to Omit:
                // But we can't do that here without invalidating our totality claim
                (Overwrite{ch: a_ch, off}, Some(Purge(p_ch))) if (a_ch == p_ch) => {
                    output.push(Omit(off, 1));
                    skipping = Some(idx)
                }*/
                /* insert_omit_noop
                 * Insert(0,Z), Omit(0) => Noop*/
                (Insert{off,ch}, Some(Omit(opos, olen))) if (opos == off) => {
                    // it's definitely going away
                    match olen {
                        1 => { // becomes 0 after decrementing
                            output.push(Noop);
                        }
                        0 => { // Omit(_,0) is a no-op:
                            output.push(Insert{off,ch});
                        }
                        _ => {
                            // opos +1 (insert pos) -1 (inserted value)== opos
                            output.push(Omit(opos, olen-1));
                        }
                    }
                    skipping = Some(idx+1);
                }
                /* Insert{off=0,ch}, Some(Swap(0,1)) => Insert(x,ch) */
                /*(Insert{off: 0,ch}, Some(Swap(0,1))) => {
                    /* should be a more generalizable */
                    skipping = Some(idx+1);
                    output.push(Insert{off: 1, ch});
                }*/
                /* Rotating forth and back is a no-op: */
                (RotateRight, Some(RotateLeft)) => { skipping = Some(idx+1) }
                (RotateLeft, Some(RotateRight)) => { skipping = Some(idx+1) }
                /* i0a i0b D1 => i0b */

                /* Purging the same character twice is idempotent */
                (Purge(ch1), Some(Purge(ch2))) if (ch1 == ch2) => {
                    skipping = Some(idx);
                }
                /* Replacing twice does no good either: */
                (Replace(a,b), Some(Replace(a2,b2))) if (a==a2 && b==b2) => {
                    skipping = Some(idx);
                }
                /* Collapse Uppercase/Lowercase (one is enough):
                 * We could be more aggressive about this one;
                 * as long as nothing is memorized ('M'), added, etc,
                 * we could look ahead like "u [ } l" => l
                 */
                (Uppercase, Some(Uppercase)) => { output.push(e);
                                                  skipping = Some(idx+1) }
                (Lowercase, Some(Lowercase)) => { output.push(e);
                                                  skipping = Some(idx+1) }
                (Uppercase, Some(Lowercase)) => {
                    skipping=Some(idx); /* don't push Uppercase */ }
                (Lowercase, Some(Uppercase)) => {
                    skipping=Some(idx); /* don't push Lowercase */ }

                /* Collapse overlapping delete/omit: */
                (Omit(pos1, o1), Some(Omit(pos2,o2))) if (
                    pos1 == pos2
                        && (o1 + o2 < 35) /* test_minimize_rule_regression_01_omit_unrepresentable */
                ) => {
                    output.push(Omit(pos1, o1+o2));
                    skipping = Some(idx+1);
                }
                (Omit(pos1, o1), Some(Omit(pos2,o2))
                ) if pos2 < pos1 && pos1 == pos2+o2 => {
                    // TODO bounds checking here needs a brain to take pity on it
                    output.push(Omit(pos2, o1+o2));
                    skipping = Some(idx+1);
                }
                _ => {
                    /* We didn't manage to optimize anything for this Inst. */
                    //dbg!("boring {:?}", e);
                    output.push(e);
                }
            }
        }
        match skipping {
            None => {
                //dbg!("done rewriting: {:?} -> {:?}", input, output);
                break;
            }
            Some(_) => {
                /*
                 * Ensure termination / totality / that we make progress
                 * instead of hitting endless loops.
                 */
                 // output is smaller, in general (minifier works):
                assert!(input.len() > output.len());
                // this pass made it smaller (we made progres):
                assert!(workvec.len() > output.len());
                workvec.truncate(0);
                for &inst in output.iter() {
                    workvec.push(inst);
                }
                output.truncate(0);
                //println!("rewrote {:?}\nto\t{:?}", input, workvec);
                continue; /*keep rewriting*/
            }
        }
    }
    assert!(input.len() >= output.len()); // don't make it bigger at least
    if output.len() == 0 && input.len() != 0 {
        /* Ensure we at least emit a ':' */
        output.push(Noop);
    }
}

/*
 * Evaluate a single instruction and apply the change to
 * the mutable vector.
 * In line with hashcat, invalid instructions are silently
 * ignored (but I haven't validated that the behaviour is
 * identical).
 */
pub fn evaluate_inst(inst: Inst, input: &mut Vec<u8>) {
    use crate::Inst::*;
    match inst {
        Noop => {},
        Lowercase => {
            input.make_ascii_lowercase();
            /* well that was certainly easier than
            for ch in input.iter_mut() {
                if 'A' as u8 <= *ch && *ch <= 'Z' as u8 {
                    *ch = *ch + 0x20;
                }
            }*/
        },
        Uppercase => { input.make_ascii_uppercase(); }
        RotateLeft => { if input.len() > 1 { input.rotate_left(1); } }
        RotateRight => { if input.len() > 1 { input.rotate_right(1); } }
        Reverse => { input.reverse(); }
        DeleteLastCharacter => {
            if input.len() > 0 {
                input.truncate(input.len()-1);
            }
        }
        Extract(pos,amount) => {
            let pos = pos as usize;
            if pos < input.len() { // x is no-op when pos >= len
                let extracted = input[
                    (pos as usize)..std::cmp::min(pos+amount as usize, input.len())
                ].to_vec();
                input.clear();
                input.extend(extracted);
            }
        }
        Omit(pos, amount) => {
            /* clip to bounds: */
            let pos = std::cmp::min(pos as usize, input.len());
            let top = std::cmp::min(pos + amount as usize, input.len());
            input.splice(pos as usize .. top, []);
        }
        Swap(n,m) => {
            // https://doc.rust-lang.org/std/primitive.slice.html#method.swap
            if (std::cmp::max(n,m) as usize) < input.len() {
                input.swap(n as usize, m as usize);
            }
        },
        SwapBack => {
            // a=input.pop;b=input.pop;input.push(b);input.push(a);
            let len = input.len();
            if 2 <= len {
                input.swap(len-1, len-2);
            }
        },
        Append(ch) => { input.push(ch); }
        Insert{off,ch} => {
            /* ignored when OOB: */
            if (off as usize) <= input.len() {
                input.splice(off as usize .. off as usize, [ch]);
            }
        }
        Overwrite{off,ch} => {
            /* TODO uncertain how this should react to OOB writes */
            if (off as usize) < input.len() {
                input[off as usize] = ch;
            }
        }
        Purge(ch) => {
            input.retain(|&o| o != ch);
        }
        Replace(old_ch, new_ch) => {
            for cur in input.iter_mut() {
                if *cur == old_ch {
                    *cur = new_ch;
                }
            }
        }
    }
}

pub fn evaluate_rule(rule: Vec<Inst>, mangled: &mut Vec<u8>) {
    for &inst in rule.iter() {
        evaluate_inst(inst, mangled);
    }
}

use nom::{
    Parser,
    IResult,
    error::context, // provide stack name for debugging/error msgs
    branch::alt, // choice
    character::complete::one_of, // choice of chars
    character::complete::space0, // space and tab, 0 or more
    error::VerboseError,
    character::complete::char,
    sequence::preceded, // *>
    multi::many0,
    sequence::terminated, // <*
    combinator::all_consuming, // verify there's nothing leftover
};

/*
 * Parse arity/0 instructions.
 */
fn parse_inst0(i: &str) -> IResult<&str, Inst, VerboseError<&str>> {
    let (i, t) = context("inst/0", one_of(":lur}{][kK"))(i)?;
    use crate::Inst::*;
    Ok((i,
        match t {
            ':' => { Inst::Noop },
            'l' => { Inst::Lowercase },   // p@ssW0rd -> p@ssw0rd
            'u' => { Inst::Uppercase },   // p@ssW0rd -> P@SSW0RD
            'r' => { Inst::Reverse },     // p@ssW0rd -> dr0Wss@p
            '{' => { Inst::RotateLeft },  // p@ssW0rd -> @ssW0rdp
            '}' => { Inst::RotateRight }, // p@ssW0rd -> dp@ssW0r
            '[' => { Inst::Omit(0,1) },   // p@ssW0rd -> @ssW0rd
            ']' => { Inst::DeleteLastCharacter } // p@ssW0rd -> p@ssW0r
            'k' => { Swap(0,1) }  // p@ssW0rd -> @pssW0rd
            'K' => { SwapBack }   // p@ssW0rd -> p@ssW0dr
            _ => unreachable!(),
        },
    ))
}

/*
 * Parse a single-digit offset in the 0..9A..Z format.
 */
fn parse_offset(i: &str) -> IResult<&str, u8, VerboseError<&str>> {
    nom::character::complete::satisfy(
        |c:char| ('0' <= c && c <= '9')
    ).map(|c| c as u8 - '0' as u8).or(
        nom::character::complete::satisfy(
            |c:char| ('A' <= c && c <= 'Z')
        ).map(|c| 10 + c as u8 - 'A' as u8)
    ).parse(i)
}

fn unparse_offset(off: u8) -> char {
    match off {
        0 ..= 9 => { (off+0x30) as char}
        10..=35 => { (off+0x41-10) as char}
        _ => { panic!("offset out of range") }
    }
}

/*
 * TODO: note that 'anychar' should accept
 * backslash-escaped hex too:
 */
fn hashcat_char(i: &str) -> IResult<&str, u8, VerboseError<&str>> {
    nom::character::complete::anychar.map(|ch| ch as u8).parse(i)
}

/*
 * Parse arity/1 instructions.
 */
fn parse_inst1(i: &str) -> IResult<&str, Inst, VerboseError<&str>> {
    use crate::Inst::*;
    context(
        "inst/1",
        alt((
            preceded(char('D'), parse_offset).map(|off| Inst::Omit(off,1)),
            preceded(char('@'), hashcat_char).map(|ch| Purge(ch)),
            preceded(char('$'), hashcat_char).map(|ch| Append(ch)),
            preceded(char('^'), hashcat_char).map(|ch| Insert{off:0,ch}),
        )))(i)
}

/*
 * Parse arity/2 instructions.
 */
fn parse_inst2(i: &str) -> IResult<&str, Inst, VerboseError<&str>> {
    use crate::Inst::*;
    context(
        "inst/2",
        alt((
            preceded(char('*'), parse_offset.and(parse_offset)).map(|(n,m)| Swap(n,m)),
            preceded(char('O'), parse_offset.and(parse_offset)).map(|(n,m)| Omit(n,m)),
            preceded(char('x'), parse_offset.and(parse_offset)).map(|(n,m)| Extract(n,m)),
            preceded(char('o'), parse_offset.and(hashcat_char)).map(|(off,ch)| Overwrite{off,ch}),
            preceded(char('i'), parse_offset.and(hashcat_char)).map(|(off,ch)| Insert{off,ch}),
            preceded(char('s'), hashcat_char.and(hashcat_char)).map(|(old,new)| Replace(old,new)),
        )))(i)
}

/*
 * Catch-all instruction parser for all arities.
 */
fn parse_inst(i: &str) -> IResult<&str, Inst, VerboseError<&str>> {
    context(
        "inst",
        alt((
            parse_inst0,
            parse_inst1,
            parse_inst2,
        )))(i)
}

use core::str::FromStr;
impl FromStr for Inst {
    type Err = String;
    fn from_str(s: &str) -> Result<Inst, String> {
        context("parse_inst", parse_inst)(s)
            .map_err(|e: nom::Err<VerboseError<&str>>| format!("{:#?}", e))
            .map(|(_loc, res)| res)
    }
}

/*
 * Parse a complete rule (a series of instructions separated by whitespace).
 * TODO: NOT handled:
 * - comments ('#')
 * - newline terminating
 */
pub fn parse_rule(i: &str) -> Result<Vec<Inst>, String> {
    context(
        "rule",
        all_consuming(
            terminated(
                many0(space0
                      .and(parse_inst).map(|(_ws,inst)|inst)),
                space0
            )
        )
    )(i)
        .map_err(|e: nom::Err<VerboseError<&str>>| format!("{:#?}", e))
        .map(|(_loc, res)| res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_offset() {
        assert_eq!(parse_offset("0"), Ok(("", 0)));
        assert_eq!(parse_offset("1"), Ok(("", 1)));
        assert_eq!(parse_offset("9"), Ok(("", 9)));
        assert_eq!(parse_offset("A"), Ok(("", 10)));
    }

    #[test]
    fn test_unparse_offset() {
        /* best-effort test that unparse_offset roughly corresponds
         * to parse_offset, at least for legal values.
         */
        for ch in '\x00'..='\x7f' {
            match parse_offset(&String::from(ch)) {
                Ok((_, off)) => {
                    assert_eq!(ch, unparse_offset(off))
                }
                Err(_) => { /* ideally would ensure nothing decode to this */ }
            }
        }
    }

    /*
     * Minimizer inputs that should *not* be shortened.
     */
    #[test]
    fn test_minimize_rule_refl() {
        use crate::Inst::*;

        /* Blank lines aren't rules: */
        let rule = vec![]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(rule, rule_out);

        let rule = vec![Noop]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(rule, rule_out);

        let rule = vec![Lowercase]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(rule, rule_out);

        let rule = vec![Reverse]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(rule, rule_out);

    }
    #[test]

    /*
     * Tests for minimizer productions.
     */
    fn test_minimize_rule() {
        use crate::Inst::*;

        let rule = vec![Noop, Append(b'a'), Noop, Append(b'B')]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Append(b'a'), Append(b'B')], rule_out);

        let rule = vec![RotateLeft, RotateRight]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Noop], rule_out);

        let rule = vec![Lowercase, Uppercase]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(vec![Uppercase], rule_out);

        let rule = vec![SwapBack,SwapBack]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(vec![Noop], rule_out);

        let rule = vec![Swap(1,4),Swap(4,1)]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(vec![Noop], rule_out);

        let rule = vec![Reverse,Reverse]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(vec![Noop], rule_out);

        /* // This optimization would be valid for pw.len() > 1,
           // but i1a is a no-op when pw.len() == 0:
        let rule = vec![Insert{off:0,ch: b'a'}, Swap(0,1)];
        let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Insert{off:1, ch:b'a'}], rule_out);
        */

        let rule = vec![Lowercase, Lowercase]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(vec![Lowercase], rule_out);

        let rule = vec![Lowercase, Noop, Uppercase]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out); assert_eq!(vec![Uppercase], rule_out);

        let rule = vec![Lowercase, Lowercase, Lowercase];
        let mut rule_out = vec![]; minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Lowercase], rule_out);

        let rule = vec![Lowercase, Uppercase,
                        Lowercase, Lowercase];
        let mut rule_out = vec![]; minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Lowercase], rule_out);

        let rule = vec![RotateLeft, RotateLeft,
                        RotateRight, RotateRight];
        let mut rule_out = vec![]; minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Noop], rule_out);

        let rule = vec![Omit(0,1), Omit(0,1), Omit(0,1)]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Omit(0,3)], rule_out);

        let rule = vec![Omit(1,1), Omit(0,1)]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Omit(0,2)], rule_out);

        let rule = vec![Omit(2,1), Omit(0,1)]; let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Omit(2,1), Omit(0,1)], rule_out);

        let rule = vec![Insert { off: 0, ch: b'a' }, RotateLeft];
        let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Append(b'a')], rule_out);

        let rule = vec![Append ( b'a'), RotateRight];
        let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Insert{off:0,ch:b'a'}], rule_out);

        let rule = vec![Insert { off: 0, ch: 97 },
                        RotateLeft,
                        RotateRight,
                        Overwrite { off: 0, ch: b'x' }];
        let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Insert{off:0,ch:b'x'}], rule_out);

        let rule = vec![Append(b'a'), Purge(b'a')];
        let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Purge(b'a')], rule_out);

        let rule = vec![Insert{off:0,ch:b'a'}, Purge(b'a')];
        let mut rule_out = vec![];
        minimize_rule(&rule, &mut rule_out);
        assert_eq!(vec![Purge(b'a')], rule_out);

    }

    #[test]
    fn test_parse_inst() {
        assert_eq!(parse_inst(":"), Ok(("", Inst::Noop)));
        assert_eq!(parse_inst("l"), Ok(("", Inst::Lowercase)));
        assert_eq!(parse_inst("u"), Ok(("", Inst::Uppercase)));
        assert_eq!(parse_inst("r"), Ok(("", Inst::Reverse)));
        assert_eq!(parse_inst("{"), Ok(("", Inst::RotateLeft)));
        assert_eq!(parse_inst("}"), Ok(("", Inst::RotateRight)));
        assert_eq!(parse_inst("k"), Ok(("", Inst::Swap(0,1))));
        assert_eq!(parse_inst("K"), Ok(("", Inst::SwapBack)));
        assert_eq!(parse_inst("["), Ok(("", Inst::Omit(0,1))));
        assert_eq!(parse_inst("]"), Ok(("", Inst::DeleteLastCharacter)));
        assert_eq!(parse_inst("D0"), Ok(("", Inst::Omit(0,1))));
        assert_eq!(parse_inst("DB"), Ok(("", Inst::Omit(11,1))));
        assert_eq!(parse_inst("*01"), Ok(("", Inst::Swap(0,1))));
        assert_eq!(parse_inst("*10"), Ok(("", Inst::Swap(1,0))));
        assert_eq!(parse_inst("$a"), Ok(("", Inst::Append('a' as u8))));
        assert_eq!(parse_inst("O47"), Ok(("", Inst::Omit(4,7))));
        assert_eq!(parse_inst("i4x"), Ok(("", Inst::Insert{off:4,ch:b'x'})));
        assert_eq!(parse_inst("o4x"), Ok(("", Inst::Overwrite{off:4,ch:b'x'})));
        assert_eq!(parse_inst("@4"), Ok(("", Inst::Purge(b'4'))));
        assert_eq!(parse_inst("s47"), Ok(("", Inst::Replace(b'4',b'7'))));
        //assert_eq!(parse_inst("x"), Ok(("", Inst::Noop)));
    }

    /*
     * Tests whitespace separation between instructions
     */
    #[test]
    fn test_parse_rule_spacing() {
        assert_eq!(parse_rule(":"), Ok(vec![Inst::Noop]));
        assert_eq!(parse_rule("::"), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(":: "), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(": :"), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(" ::"), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(": : "), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(" : :"), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(" : : "), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(" : \t : "), Ok(vec![Inst::Noop, Inst::Noop]));
        assert_eq!(parse_rule(":\t"), Ok(vec![Inst::Noop]));
    }

    #[test]
    fn test_minimize_rule_regression_01_omit_unrepresentable() {
        let rule = parse_rule("OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO").unwrap();
        let mut buf = Vec::new();
        minimize_rule(&rule,&mut buf);
    }

    #[test]
    fn test_minimize_rule_regression_02_insert_swap_omit() {
        let pw = [b'a',b'b',b'c'];
        let rule = parse_rule("i0a *01 D0").unwrap();
        let mut minrule = Vec::new();
        minimize_rule(&rule,&mut minrule);
        assert_ne!(minrule, vec![Inst::Noop]);
        let mut mangled_min = pw.to_vec();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        evaluate_rule(minrule.clone(), &mut mangled_min);
        assert_eq!(mangled_min, mangled_big, "{:?} /// {:?}", minrule, rule);
    }

    /*
     * While the optimization iX DX => : looks good,
     * it only works if iX succeeds (if the candidate word
     * is already large enough).
     * Our current implementation appends to the end, but
     * it remains to be tested how hashcat reacts.
     * if hashcat ignores OOB inserts, we can turn this back on.
     */
    #[test]
    fn test_minimize_rule_regression_03_insert_omit_noop() {
        let pw = [b'a',b'b',b'c'];
        let rule = parse_rule("i9e D9").unwrap();
        let mut minrule = Vec::new();
        minimize_rule(&rule,&mut minrule);
        assert_eq!(minrule, vec![Inst::Noop]);
        assert_ne!(rule, vec![Inst::Noop]);
        assert_ne!(rule, minrule);
        let mut mangled_min = pw.to_vec();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        evaluate_rule(minrule.clone(), &mut mangled_min);
        assert_eq!(mangled_min, mangled_big, "{:?} /// {:?}", minrule, rule);
    }

    #[test]
    fn test_minimize_rule_regression_04_insert_swap() {
        let mut pw = vec![];
        for _ in 0..=4 {
            /* Insert{off:0,ch=b'-'}, Swap(0,1)
             * should not reduce to Noop
             * because that fails when pw.len() <= 1
             */
            let rule = parse_rule("i0-k").unwrap();
            let mut minrule = Vec::new();
            minimize_rule(&rule,&mut minrule);
            assert_ne!(rule, vec![Inst::Noop]);
            assert_eq!(rule, minrule);
            let mut mangled_min = pw.to_vec();
            let mut mangled_big = pw.to_vec();
            evaluate_rule(rule.clone(), &mut mangled_big);
            evaluate_rule(minrule.clone(), &mut mangled_min);
            assert_eq!(mangled_min, mangled_big, "{:?} /// {:?} /// pw:{:?}", minrule, rule, pw);
            pw.push(b'X');
        }
    }

    #[test]
    fn test_minimize_rule_regression_05_omit0() {
        let pw = vec![b'A'];
        let rule = parse_rule("O00").unwrap();
        let mut minrule = Vec::new();
        minimize_rule(&rule,&mut minrule);
        assert_ne!(rule, vec![Inst::Noop]);
        assert_eq!(minrule, vec![Inst::Noop]);
        let mut mangled_min = pw.to_vec();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        evaluate_rule(minrule.clone(), &mut mangled_min);
        assert_eq!(mangled_min, mangled_big, "{:?} /// {:?} /// pw:{:?}", minrule, rule, pw);
    }
    #[test]
    fn test_minimize_rule_regression_05_reverse_omit0() {
        /* O00 is a no-op, so this should minimize to Reverse(r): */
        let rule = parse_rule("rO00").unwrap();
        let mut minrule = Vec::new();
        minimize_rule(&rule,&mut minrule);
        assert_ne!(rule, vec![Inst::Noop]);
        assert_eq!(minrule, vec![Inst::Reverse]);
    }

    #[test]
    fn test_minimize_rule_regression_05_prepend_omit0() {
        let pw = vec![b'A'];
        let rule = parse_rule("^aO00").unwrap();
        let mut minrule = Vec::new();
        minimize_rule(&rule,&mut minrule);
        assert_ne!(rule, vec![Inst::Noop]);
        assert_eq!(minrule, vec![Inst::Insert{off:0,ch:b'a'}]);
        let mut mangled_min = pw.to_vec();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        evaluate_rule(minrule.clone(), &mut mangled_min);
        assert_eq!(mangled_min, mangled_big, "{:?} /// {:?} /// pw:{:?}", minrule, rule, pw);
    }

    /*
     * Check that starting offset >= input.len() is a no-op
     */
    #[test]
    fn test_minimize_rule_regression_06_extract_oob_index() {
        let pw = vec![b'A',b'B',b'C'];
        let rule = parse_rule("xK1").unwrap();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        assert_eq!(vec![b'A',b'B',b'C'], mangled_big,
                   "{:?} /// {:?} /// pw:{:?}", rule, mangled_big, pw);
        let rule = parse_rule("x31").unwrap();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        assert_eq!(vec![b'A',b'B',b'C'], mangled_big,
                   "{:?} /// {:?} /// pw:{:?}", rule, mangled_big, pw);
        let rule = parse_rule("x30").unwrap();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        assert_eq!(vec![b'A',b'B',b'C'], mangled_big,
                   "{:?} /// {:?} /// pw:{:?}", rule, mangled_big, pw);
        let rule = parse_rule("x21").unwrap();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        assert_eq!(vec![b'C'], mangled_big,
                   "{:?} /// {:?} /// pw:{:?}", rule, mangled_big, pw);
        /* entire range (overshooting): */
        let rule = parse_rule("x0K").unwrap();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        assert_eq!(vec![b'A',b'B',b'C'], mangled_big,
                   "{:?} /// {:?} /// pw:{:?}", rule, mangled_big, pw);
        /*
         * smaller range:
         * # echo 'abc' | hashcat --stdout -j 'x02'
         * ab
         */
        let rule = parse_rule("x02").unwrap();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        assert_eq!(vec![b'A',b'B'], mangled_big,
                   "{:?} /// {:?} /// pw:{:?}", rule, mangled_big, pw);
        /*
         * empty range:
         * # echo 'abc' | hashcat --stdout -j 'x10'
         *
         */
        let rule = parse_rule("x00").unwrap();
        let mut mangled_big = pw.to_vec();
        evaluate_rule(rule.clone(), &mut mangled_big);
        assert_eq!(mangled_big, vec![],
                   "{:?} /// {:?} /// pw:{:?}", rule, mangled_big, pw);
    }

    /*
     * Tests for evaluation of instruction that take offsets that might point
     * somewhere outside of the candidate buffer. Mainly here to ensure these
     * don't result in panics.
     */
    #[test]
    fn test_evaluate_inst_omit_underflow() {
        let mut arr = vec![b'A',b'b'];
        evaluate_inst(Inst::Omit(0,1), &mut arr);
        assert_eq!(arr, [b'b']);
        evaluate_inst(Inst::Omit(0,1), &mut arr);
        assert_eq!(arr, []);
        /* this used to crash due to negative bounds: */
        evaluate_inst(Inst::Omit(0,1), &mut arr);
        assert_eq!(arr, []);
        evaluate_inst(Inst::Omit(3,2), &mut arr);
        assert_eq!(arr, []);
        let mut arr = vec![b'A',b'b',b'c'];
        evaluate_inst(Inst::Omit(0,100), &mut arr);
        assert_eq!(arr, []);
        let mut arr = vec![b'A',b'b',b'c'];
        evaluate_inst(Inst::Omit(2,100), &mut arr);
        assert_eq!(arr, [b'A',b'b']);
    }

    /*
     * Tests for the Insert instruction, exercising out-of-bounds
     * insertions (which should be ignored).
     */
    #[test]
    fn test_evaluate_inst_insert_oob() {
        let mut arr = vec![];
        evaluate_inst(Inst::Insert{off:100,ch:b'B'}, &mut arr);
        assert_eq!(arr, []);
        arr.push(b'A');
        evaluate_inst(Inst::Insert{off:0,ch:b'B'}, &mut arr);
        assert_eq!(arr, [b'B',b'A']);
        evaluate_inst(Inst::Insert{off:2,ch:b'C'}, &mut arr);
        assert_eq!(arr, [b'B',b'A',b'C']);
        evaluate_inst(Inst::Insert{off:4,ch:b'C'}, &mut arr);
        assert_eq!(arr, [b'B',b'A',b'C']);
        evaluate_inst(Inst::Insert{off:5,ch:b'D'}, &mut arr);
        assert_eq!(arr, [b'B',b'A',b'C']);
    }

    /*
     * Some basic coverage of the instruction evaluator.
     */
    #[test]
    fn test_evaluate_inst() {
        let mut arr = vec![b'A',b'b',b'C'];
        evaluate_inst(Inst::Noop, &mut arr);
        assert_eq!(arr, [b'A',b'b',b'C']);
        evaluate_inst(Inst::Replace(b'b',b'0'), &mut arr);
        assert_eq!(arr, [b'A',b'0',b'C']);
        evaluate_inst(Inst::Replace(b'0',b'b'), &mut arr);
        assert_eq!(arr, [b'A',b'b',b'C']);
        evaluate_inst(Inst::Append(0x64), &mut arr);
        assert_eq!(arr, [b'A', b'b', b'C', b'd']);
        evaluate_inst(Inst::Uppercase, &mut arr);
        assert_eq!(arr, [b'A', b'B', b'C', b'D']);
        evaluate_inst(Inst::Lowercase, &mut arr);
        assert_eq!(arr, [b'a', b'b', b'c', b'd']);
        evaluate_inst(Inst::RotateLeft, &mut arr);
        assert_eq!(arr, [b'b', b'c', b'd', b'a']);
        evaluate_inst(Inst::RotateRight, &mut arr);
        assert_eq!(arr, [b'a', b'b', b'c', b'd']);
        evaluate_inst(Inst::Reverse, &mut arr);
        assert_eq!(arr, [b'd', b'c', b'b', b'a']);
        evaluate_inst(Inst::DeleteLastCharacter, &mut arr);
        assert_eq!(arr, [b'd', b'c', b'b']);
        evaluate_inst(Inst::Omit(1,1), &mut arr);
        assert_eq!(arr, [b'd', b'b']);
        evaluate_inst(Inst::Append(b'A'), &mut arr);
        assert_eq!(arr, [b'd', b'b', b'A']);
        evaluate_inst(Inst::Omit(0,2), &mut arr);
        assert_eq!(arr, [b'A']);
        evaluate_inst(Inst::DeleteLastCharacter, &mut arr);
        assert_eq!(arr, []);
        evaluate_inst(Inst::Insert{off: 0,ch:b'A'}, &mut arr);
        assert_eq!(arr, [b'A']);
        evaluate_inst(Inst::Append(b'C'), &mut arr);
        assert_eq!(arr, [b'A',b'C']);
        /* Swap(N,M) is a no-op if N,M >= arr.len() */
        evaluate_inst(Inst::Swap(0,2), &mut arr);
        assert_eq!(arr, [b'A',b'C']);
        evaluate_inst(Inst::Swap(2,0), &mut arr);
        assert_eq!(arr, [b'A',b'C']);
        evaluate_inst(Inst::Swap(2,1), &mut arr);
        assert_eq!(arr, [b'A',b'C']);
        evaluate_inst(Inst::Swap(1,2), &mut arr);
        assert_eq!(arr, [b'A',b'C']);
        evaluate_inst(Inst::Insert{off: 1, ch: b'B'}, &mut arr);
        assert_eq!(arr, [b'A',b'B', b'C']);
        evaluate_inst(Inst::Insert{off: 2, ch: b'b'}, &mut arr);
        assert_eq!(arr, [b'A',b'B',b'b', b'C']);
        evaluate_inst(Inst::Overwrite{off: 2, ch: b'3'}, &mut arr);
        assert_eq!(arr, [b'A',b'B',b'3', b'C']);
        evaluate_inst(Inst::SwapBack, &mut arr);
        assert_eq!(arr, [b'A',b'B',b'C', b'3']);
        evaluate_inst(Inst::Swap(0,2), &mut arr);
        assert_eq!(arr, [b'C',b'B',b'A', b'3']);
        evaluate_inst(Inst::Insert{off:1, ch:b'1'}, &mut arr);
        assert_eq!(arr, [b'C',b'1',b'B',b'A', b'3']);
        evaluate_inst(Inst::Insert{off:1, ch:b'2'}, &mut arr);
        assert_eq!(arr, [b'C',b'2',b'1',b'B',b'A', b'3']);
        evaluate_inst(Inst::Omit(1,2), &mut arr);
        assert_eq!(arr, [b'C',b'B',b'A', b'3']);
        evaluate_inst(Inst::Extract(1,2), &mut arr);
        assert_eq!(arr, [b'B',b'A',]);
        evaluate_inst(Inst::Append(b'c'), &mut arr);
        evaluate_inst(Inst::Append(b'd'), &mut arr);
        assert_eq!(arr, [b'B',b'A',b'c',b'd']);
        evaluate_inst(Inst::Extract(1,3), &mut arr);
        assert_eq!(arr, [b'A',b'c',b'd']);
        evaluate_inst(Inst::Extract(1,10), &mut arr);
        assert_eq!(arr, [b'c',b'd']);
        evaluate_inst(Inst::Purge(b'd'), &mut arr);
        assert_eq!(arr, [b'c']);
    }
}
