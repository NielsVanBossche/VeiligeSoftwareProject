//This program reads your name through stdin and greets you
//A name can only contain alphabetical characters and cannot be empty

//TODO fix the compiler errors and have a look at the warnings

//This program uses `panic!()` to deal with names that do not comply with the name format
//Using `panic!()` is a quick-and-dirty way to do error handling, however, it has the obvious drawback that it is all-or-nothing: you cannot recover from it (in general)

//TODO change to program so it doesn't panic on malformatted names, and handle the compiler warnings
//We have provided an error type for properly reporting all errors that `get_username` might generate
//Change `get_username` so it returns a `Result<String, MyError>` and handle the errors in `main` (an IOError should quit the program, but after an InvalidName error it should repeat the question to the user)
//hint: have a look at `Result`s `or_else` function, and the `?` operator


enum MyError {
    InvalidName,
    IOError(io::Error),
}

fn get_username() -> String {
    print!("Username: ");
    io::stdout().flush();

    let mut input = String::new();
    io::stdin().lock().read_line(&mut input);
    input = input.trim().to_string(); //have a look at the docs to see what `trim` does

    for c in input.chars() {
        if !char::is_alphabetic(c) {
            panic!("that's not a valid name, try again");
        }
    }

    if input.is_empty() {
        panic!("that's not a valid name, try again");
    }

    input
}

fn main() {
    let name = get_username();
    println!("Hello {name}!")
}
