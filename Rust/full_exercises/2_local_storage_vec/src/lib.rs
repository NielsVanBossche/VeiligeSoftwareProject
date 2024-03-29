//In this exercise, you will implement the LocalStorageVec data structure, which
//is a growable, generic list that resides either on the stack (if its size is below a
//given number `N`), or on the heap if it grows larger
//This list is generic over the element type `T`, as well as the size `N` of the stack allocated buffer

//You may have noticed that this is a lib.rs file and not a main.rs file
//This file naming convention is one possibility to tell Cargo to build a static library instead of an application binary
//There is thus no `main` function in which you can test your code, instead we wrote some tests inside the module called `test` at the bottom of the file
//You can run the tests with `cargo test`


//TODO 1: complete the implementation of the LocalStorageVec enum
//Define a variant called `Stack` containing two named fields:
// - `buf` is an array with elements of type `T` and size `N`
// - `len` is a field of type `usize` (len represents the number of elements currently in the array, while the const-generic `N` represents its capacity)
//Define a variant called `Heap`, containing a single unnamed field of type `Vec<T>`, which is a heap-based growable, contiguous list of type `T`
//(you can find more info about when each variant is used in TODO 2)
pub enum LocalStorageVec<T, const N: usize> {

}

//The `std::convert::From` and `std::convert::Into` traits allow a type to be easily created FROM
//another type, or be converted INTO another type, respectively.
//The String type, for example, implements the `From<&str>` trait (https://doc.rust-lang.org/std/string/struct.String.html#impl-From%3C%26str%3E-for-String) which makes the following code valid:
//  let my_str: &str = "hello";
//  let my_string: String = String::from(my_str);
//TODO 2 implement the `From<[T; N]>` trait on your LocalStorageVec type so you can create a LocalStorageVec from an array
//As you can see, `N` (size of the given array) can differ from `M` (max size of the stack allocated buffer):
// - if N == M: the buffer is allocated on the stack and has exactly, and only the elements of the given array (the LocalStorageVec enum has the `Stack` variant)
// - if N < M: the buffer is allocated on the stack and contains all elements of the given array (the LocalStorageVec enum has the `Stack` variant)
//             the M-N leftover elements are filled with "default values" (instead of uninitialized memory, for simplicity), that is why we bound the type T to implement the `Default` trait
//             note: the syntax `impl<T>... where T: Default` is the same as `impl<T: Default>...`
// - if N > M: the buffer is allocated on the heap and contains all elements of the given array
//             nothing is allocated on the stack (the LocalStorageVec enum has the `Heap` variant)
impl<T, const N: usize, const M: usize> From<[T; N]> for LocalStorageVec<T, M>
where T: Default {
  fn from(array: [T; N]) -> Self {
        if N <= M {
           
        } else {
          //hint: `Vec<T>` implements the `From<[T,N]>` trait, see the docs
          
        }
    }
}

//TODO 3: complete these functions
//To make implementation easier, you should bound `T` to implement `Copy` and `Default`
impl<T, const N: usize> LocalStorageVec<T, N> {

    //returns an empty LocalStorageVec without heap allocation
    pub fn new() -> LocalStorageVec<T, N> {

    }

    //return the current number of elements
    pub fn len(???) -> usize {

    }

    //insert a new element at the back
    //if the size exceeds the stack allocated buffer size, the whole buffer is moved to the heap
    pub fn push(???) {
        
    }

    //pop and return the last element
    //if the size gets equal to the stack allocated buffer size, the buffer gets moved back to the stack
    //(whether or not this is efficient behaviour is not relevant for today)
    //info: `Option` is used when there could be no result, where you would usually use some `null` value in many other impertive languages (see https://doc.rust-lang.org/std/option/index.html)
    pub fn pop(???) -> Option<T> {
        
    }
}

//TODO 4 implement the `std::ops::Index` trait to read an item at a given index in the buffer
//for example: let item: &T = my_local_storage_vec[42];


//Notice how the `Index` trait is generic over the type used for indexing
//The previous `Index<usize>` impl allows you to get single elements
//However, if the index type parameter is a `Range<usize>` type, you can create slices (= type &[T]) from your buffer
//for example: let items_slice: &[T] = my_local_storage_buffer[42..68];
//TODO 5 implement this



//DO NOT change the contents of the tests!
#[cfg(test)]
mod test {
    use crate::LocalStorageVec;

    //Tests for TODO 2
    #[test]
    fn test_new() {
        let vec: LocalStorageVec<usize, 10> = LocalStorageVec::new();
        // Assert that the call to `new` indeed yields a `Stack` variant with zero length
        assert!(matches!(vec, LocalStorageVec::Stack { buf: _, len: 0 }));
    }

    #[test]
    fn test_len() {
        let vec: LocalStorageVec<_, 3> = LocalStorageVec::from([0, 1, 2]);
        assert_eq!(vec.len(), 3);
        let vec: LocalStorageVec<_, 2> = LocalStorageVec::from([0, 1, 2]);
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn test_push() {
        let mut vec: LocalStorageVec<_, 128> = LocalStorageVec::new();
        for value in 0..128 {
            vec.push(value);
        }
        assert!(matches!(vec, LocalStorageVec::Stack { len: 128, .. }));

        for value in 128..256 {
            vec.push(value);
        }
        assert!(matches!(vec, LocalStorageVec::Heap(v) if v.len() == 256))
    }

    #[test]
    fn test_pop() {
        let mut vec: LocalStorageVec<_, 128> = LocalStorageVec::from([0; 128]);
        for _ in 0..128 {
            assert_eq!(vec.pop(), Some(0))
        }
        assert_eq!(vec.pop(), None);

        let mut vec: LocalStorageVec<_, 128> = LocalStorageVec::from([0; 256]);
        for _ in 0..256 {
            assert_eq!(vec.pop(), Some(0))
        }
        assert_eq!(vec.pop(), None);
    }

    //Tests for TODO 3
    #[test]
    fn test_from_array() {
        let vec: LocalStorageVec<usize, 10> = LocalStorageVec::from([1, 2, 3]);
        //assert that the call to `from` indeed yields a `Stack` variant
        assert!(matches!(vec, LocalStorageVec::Stack{..}));

        let vec: LocalStorageVec<usize, 2> = LocalStorageVec::from([1, 2, 3]);
        assert!(matches!(vec, LocalStorageVec::Heap(_)));
    }

    //Tests for TODO 4 & 5
    #[test]
    fn test_index() {
        let vec: LocalStorageVec<i32, 10> = LocalStorageVec::from([0, 1, 2, 3, 4, 5]);
        assert_eq!(vec[1], 1);
        assert_eq!(vec[0..2], [0, 1]);
        assert_eq!(vec[1..3], [1, 2]);
    }
    
}
