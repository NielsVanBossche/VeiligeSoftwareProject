//TODO fix this program in two ways (without cloning variables and without changing the print statements)

fn main() {
    let mut s0 = String::new();
    
    append_to_string(&mut s0);

    println!("{}",  s0);

    s0.push_str("!");

    println!("{}", s0);
}

//keep this function
fn append_to_string(s: &mut String) {
    s.push_str("Hello");
    s.push_str(" ");
    s.push_str("World");
}
