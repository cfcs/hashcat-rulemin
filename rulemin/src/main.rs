use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

enum ReplState {
    /* Currently only has "help" and "eval": */
    Initial,
    /* In this stage we prompt the user for dictionary words */
    Dict{
        dict: Vec<String>
    },
    /* In this stage we prompt the user for hashcat rules, then apply them
     * to the previously entered words.
     */
    Eval{
        dict: Vec<String>
    }
}

use crate::ReplState::{Initial,Eval,Dict};

fn repl() -> rustyline::Result<()> {
    let mut repl_state = ReplState::Initial;
    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(match repl_state {
            Initial => "#init# ",
            Dict{dict: _} => "#dict# ",
            Eval{dict: _} => "#eval# "
        });
        let line = match readline {
            Ok(line) => {
                /* currently undecided if we should have modal history (we don't): */
                rl.add_history_entry(line.as_str())?;
                line
            }
            Err(ReadlineError::Interrupted) => {
                // ctrl-c
                break
            }
            Err(ReadlineError::Eof) => {
                // ctrl-d
                break
            }
            Err(err) => {
                println!("rlerror: {:?}", err);
                break
            }
        };
        repl_state = match (repl_state, line.as_str()) {
            (Initial, "eval") => {
                Dict{dict: vec![]}
            }
            (Dict{dict}, "") => {
                Eval{dict: dict}
            }
            (Dict{mut dict}, word) => {
                dict.push(word.into());
                Dict{dict: dict}
            }
            (Initial, line) => {
                println!("Help: {}: unrecognized command.", line);
                println!("Valid commands: eval");
                Initial
            }
            (Eval{dict}, line) => {
                use term_table::{TableStyle};
                use term_table::table_cell::Alignment;
                use term_table::table_cell::TableCell;
                use term_table::row::Row;
                let mut table = term_table::Table::new();
                table.max_column_width = 35;
                table.style = TableStyle::thin();
                table.add_row({
                    let mut r = Row::new(vec![
                    TableCell::new_with_alignment(line, 4, Alignment::Center)
                    ]);
                    r.has_separator = false;
                    r
                });
                match rulelib::parse_rule(line) {
                    Ok(rule) => {
                        table.add_row(Row::new(vec![
                            TableCell::new_with_col_span(format!("{:?}", rule), 4)
                        ]));
                        let mut optimized = vec![];
                        rulelib::minimize_rule(&rule, &mut optimized);
                        table.add_row(Row::new(vec![
                            TableCell::new_with_col_span(
                                optimized.clone().into_iter().map(
                                    |ins|ins.to_string()).collect::<Vec<_>>()
                                    .join(" ")
                                    , 4)
                        ]));
                        table.add_row(Row::new(vec![
                            TableCell::new_with_col_span(format!("{:?}", optimized), 4)
                        ]));
                        for word in dict.iter() {
                            let mut mangled = word.as_bytes().to_vec();
                            rulelib::evaluate_rule(rule.clone(), &mut mangled);
                            table.add_row({
                                let mut r = Row::new(vec![
                                TableCell::new_with_alignment(word, 2, Alignment::Left),
                                    TableCell::new_with_alignment(
                                        String::from_utf8(mangled).unwrap(), 2, Alignment::Right),
                                ]);
                                r.has_separator = false;
                                r
                            });
                        }
                    },
                    Err(e) => {
                        println!("error: {:}", e);
                    }
                }
                table.has_bottom_boarder = false;
                print!("{}", table.render());
                Eval{dict}
            }
        };
    }
    Ok(())
}

fn main() {
    println!(r"=====================");
    println!(r"\-- rulemin repl --/");
    println!(r" ==================");
    match repl() {
        Ok(()) => {}
        Err(_) => todo!()
    }
}
