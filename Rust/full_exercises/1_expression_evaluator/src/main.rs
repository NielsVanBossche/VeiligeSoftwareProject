//TODO define an enum `Operation` with four possible operations: `Add`, `Sub`, `Mul`, `Div` on two subexpressions
enum Operation {
    Add,
    Sub,
    Mul,
    Div
}


//an `Expression` is either an operation on two subexpressions or a literal value
//info: remember that enum variants can contain data: `Op` has named fields (like a struct) and `Value` includes an unnamed signed integer
enum Expression {
    Op {
        op: Operation,
        //info: the size of stack allocatable data structures needs to be known and constant at compile time
        //However, these `left` and `right` members make `Expression` a recursive type which could have an infinite size 
        //TODO fix this issue
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Value(i64)
}


//TODO implement the evaluation of an expression (use pattern matching with the `match` keyword)
//Use integer divition for the `Div` operation
//The return type is a `Result`, which, in this case, is either an i64 on success, or a String with the error message on failure
//Look for techniques to make this function as short as possible, for example: use only a single `match` keyword (look at the pattern and destructuring syntax), and propagate errors to the caller
//This function takes ownership of the given `Expression`, DO NOT change this
//Errors can occur, for example, when dividing by 0
//Bonus TODO: return an appropriate error message on integer over/underflow
fn eval(e: Expression) -> Result<i64, String> {
    match e {
        Expression::Value(val) => Ok(val),
        Expression::Op { op, left, right } => {
            let left_val = eval(*left)?;
            let right_val = eval(*right)?;
            match op {
                Operation::Add => Ok(left_val + right_val),
                Operation::Sub => Ok(left_val - right_val),
                Operation::Mul => Ok(left_val * right_val),
                Operation::Div => {
                    if right_val == 0 {
                        Err("Division by zero".to_string())
                    } else {
                        Ok(left_val / right_val)
                    }
                }
            }
        }
    }
}


pub fn main() {
    //TODO create an expression with literal value 19
    let expr1 = Expression::Value(19);
    assert_eq!(eval(expr1), Ok(19));
    
    let expr2 = Expression::Op {
        op: Operation::Add,
        left: Box::new(Expression::Value(10)),
        right: Box::new(Expression::Value(20)),
    };
    //TODO print the result of expr2 only if there were no errors
    //hint: have a look at the `if-let` syntax
    if let Ok(result) = eval(expr2) {
        println!("{:?}", result);
    }

    let expr3 = Expression::Op {
        op: Operation::Div,
        left: Box::new(Expression::Value(99)),
        right: Box::new(Expression::Value(0)),
    };
    //TODO evaluate expr3 and print the result or the error message
    match eval(expr3) {
        Ok(result) => println!("{:?}", result),
        Err(err) => println!("{:?}", err)
    }

    let expr4 = Expression::Op {
        op: Operation::Add,
        left: Box::new(Expression::Op {
            op: Operation::Mul,
            left: Box::new(Expression::Value(10)),
            right: Box::new(Expression::Value(9)),

        }),
        right: Box::new(Expression::Op {
            op: Operation::Mul,
            left: Box::new(Expression::Value(5)),
            right: Box::new(Expression::Op {
                op: Operation::Sub,
                left: Box::new(Expression::Value(3)),
                right: Box::new(Expression::Value(4)),
            }),
        }),
    };
    match eval(expr4) {
        Ok(result) => println!("{:?}", result),
        Err(err) => println!("{:?}", err)
    }
    //TODO create, evaluate, and print the expression `(10 * 9) + (5 * (3 - 4))`

}
