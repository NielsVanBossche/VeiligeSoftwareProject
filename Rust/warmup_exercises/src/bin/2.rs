
fn main() {
    //info: the `Box` type uniquely owns a heap allocated object (see https://doc.rust-lang.org/std/boxed/struct.Box.html)
    let x = Box::new(5);
    
    //TODO define variable y as a Box to an integer

    
    //info: the `*` operator dereferences the Box to access the value it holds
    *y = 4;
    
    assert_eq!(*x, 5);

    println!("Success!");
}
