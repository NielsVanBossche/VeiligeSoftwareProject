//This is the same file as previous "GUI" exercise
//TODO: change your previous solution so it uses references instead of Boxes
//hint: this exercise is about lifetime parameters

//This is a simple GUI library 
//There are three widgets that implement the `Widget` trait: `Label`, `Button`, and `Window`
//For this exercise, you only have to print them to stdout, so the `Button` does not have any click functionality
//TODO complete the code to make it work

//info: trait objects do not have a known size at compile time, therefore, you cannot simply move its value into function arguments
//Notice how the main function uses Boxes to pass the trait objects
//This approach usually makes implementation easier because the trait objects now reside on the heap and the compiler does not need to know their size  
//Another approach is to use references to pass trait objects as function arguments

pub trait Widget {
    /// Draw the widget into a buffer.
    fn draw_into(&self, buffer: &mut dyn std::fmt::Write);

    /// Draw the widget on standard output.
    fn draw(&self) {
        let mut buffer = String::new();
        self.draw_into(&mut buffer);
        println!("{}", buffer);
    }
}

impl Widget for Label {
    fn draw_into(&self, buffer: &mut dyn std::fmt::Write) {
        write!(buffer, "{}", self.label);
    }
}

impl Widget for Button<'_> {
    fn draw_into(&self, buffer: &mut dyn std::fmt::Write) {
        write!(buffer, "| {} |", self.label.label);
    }
}

pub struct Label {
    label: String,
}

impl Label {
    fn new(label: &str) -> Label {
        Label {
            label: label.to_owned(),
        }
    }
}

pub struct Button<'a> {
    label: &'a Label,
}

impl<'a> Button<'a> {
    fn new(label: &'a Label) -> Button<'a> {
        Button {
            label,
        }
    }
}

pub struct Window<'a> {
    title: String,
    widgets: Vec<&'a dyn Widget>,
}

impl<'a> Window<'a> {
    fn new(title: &str) -> Window {
        Window {
            title: title.to_owned(),
            widgets: Vec::new(),
        }
    }

    fn add_widget(&mut self, widget: &'a dyn Widget) {
        self.widgets.push(widget);
    }

    fn draw(&mut self) {
        println!("========");
        println!("{}", self.title);
        println!("========");
        for widget in &self.widgets {
            widget.draw();
        }
    }
}

fn main() {
    let mut window = Window::new("Rust GUI Demo");
    let label = Label::new("This is a small text GUI demo.");
    let button = Button::new(&label);
    window.add_widget(&label);
    window.add_widget(&button);
    window.draw();
}
