extern crate shenango;

fn main() {
    shenango::base_init().unwrap();
    shenango::base_init_thread().unwrap();
}
