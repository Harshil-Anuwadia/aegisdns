fn main() {
    let raw = "||0--foodwarez.da.ru^";
    let line = raw.trim();
    let parts: Vec<_> = line.split_whitespace().collect();
    if parts.len() != 1 || line.contains('$') { return; }
    let line = line.strip_prefix("||").unwrap_or(line).trim_end_matches('^').trim_start_matches('.');
    println!("line: {}", line);
}
