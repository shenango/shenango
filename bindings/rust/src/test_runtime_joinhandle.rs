extern crate shenango;

use shenango::WaitGroup;
use std::sync::Arc;

const N: usize = 50000;
const NCORES: usize = 3;

fn main_handler() {
    println!("started main_handler() thread");
    println!("creating threads with 1us of fake work.");

    let wg = Arc::new(WaitGroup::new());
    wg.add(NCORES as i32);

    let start_us = shenango::microtime();

    let mut join_handles = Vec::new();
    for _ in 0..NCORES {
        join_handles.push(shenango::thread::spawn(|| {
            for _ in 0..N {
                shenango::thread::spawn(|| shenango::delay_us(1))
                    .join()
                    .unwrap();
            }
        }));
    }

    for j in join_handles {
        j.join().unwrap();
    }

    let threads_per_second =
        (NCORES * N) as f64 / ((shenango::microtime() - start_us) as f64 * 0.000001);
    println!(
        "spawned {} threads / second, efficiency {}",
        threads_per_second,
        0.000001 * threads_per_second / NCORES as f64
    );
}

fn main() {
    let args: Vec<_> = ::std::env::args().collect();
    assert!(args.len() >= 2, "arg must be config file");
    shenango::runtime_init(args[1].clone(), main_handler).unwrap();
}
