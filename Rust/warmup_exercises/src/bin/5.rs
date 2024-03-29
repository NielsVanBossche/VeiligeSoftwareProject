
struct Package {
    //TODO implement this struct based on the rest of the code
}

//info: structs contain data, but can also contain logic inside an `impl` block
impl Package {
    //info: this is a constructor (general form: `fn new(args_that_are_not_self) -> new_instance`)
    fn new(sender_country: String, recipient_country: String, weight_in_grams: u32) -> Package {
        //info: if-else structures are expressions in Rust (instead of statements)!
        if weight_in_grams < 10 {
            panic!("Can not ship a package with weight below 10 grams.")
        } else {
            Package {
                sender_country,
                recipient_country,
                weight_in_grams,
            }
        }
        //info: there is no explicit `return` here
        //Remember that a function returns the result of the last expression (if it is not terminated with a `;`)
    }

    //info: this function takes a (non-mutable) reference to self and can, therefore, access the instance itself
    fn is_international(&self) -> ??? {
        //TODO
    }

    fn get_fees(&self, cents_per_gram: u32) -> ??? {
        //TODO 
    }
}

pub fn main() {
    const CENTS_PER_GRAM: u32 = 3;

    //TODO create a package from Spain to Austria of 15 grams
    let sender_country: String = 
    let recipient_country: String = 
    let package1 = //note: be sure to use the constructor function `new`
    assert_eq!(package1.get_fees(CENTS_PER_GRAM), 45); 
    assert!(package1.is_international());

    println!("success");
}
