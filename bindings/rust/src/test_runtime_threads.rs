extern crate shenango;

use shenango::WaitGroup;
use std::os::raw::c_void;

const N: usize = 1000000;
const NCORES: usize = 4;

extern "C" fn leaf_handler(arg: *mut c_void) {
    let wg_parent = unsafe { &*(arg as *mut WaitGroup) };

    shenango::delay_us(1);
    wg_parent.done();
}

extern "C" fn work_handler(arg: *mut c_void) {
    let wg_parent = unsafe { &*(arg as *mut WaitGroup) };

    let wg = WaitGroup::new();
    wg.add(N as i32);
    for _ in 0..N {
        shenango::thread_spawn(leaf_handler, &wg).unwrap();
        shenango::thread_yield();
    }

    wg.wait();
    wg_parent.done();
}

extern "C" fn main_handler(_: *mut c_void) {
    println!("started main_handler() thread");
    println!("creating threads with 1us of fake work.");

    let wg = WaitGroup::new();
    wg.add(NCORES as i32);

    let start_us = shenango::microtime();
    for _ in 0..NCORES {
        shenango::thread_spawn(work_handler, &wg).unwrap();
    }

    wg.wait();

    let threads_per_second =
        (NCORES * N) as f64 / ((shenango::microtime() - start_us) as f64 * 0.000001);
    println!(
        "spawned {} threads / second, efficiency {}",
        threads_per_second,
        threads_per_second / (NCORES * 1000000) as f64
    );
}

fn main() {
    shenango::runtime_init(main_handler, &(), NCORES as u32).unwrap();
}
