use risk::score_domain;

#[test]
fn print_scores() {
    println!("{:#?}", score_domain("index.crates.io"));
}
