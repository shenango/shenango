
extern crate libc;
extern crate shenango;

use std::ptr;
use std::os::raw::c_void;

const SAMPLES: u32 = 200000;
const N: usize = (1 << 10);
const SIZE: usize = 256;

fn malloc_bench(samples: u32, ptrs: &mut [*mut c_void]) {
    for _ in 0..samples {
        for i in 0..ptrs.len() {
            ptrs[i] = unsafe { libc::malloc(SIZE) as *mut c_void };
            assert!(!ptrs[i].is_null());
        }

        for i in 0..ptrs.len() {
            unsafe { libc::free(ptrs[i] as *mut libc::c_void) };
        }
    }
}

fn smalloc_bench(samples: u32, ptrs: &mut [*mut c_void]) {
    for _ in 0..samples {
        for i in 0..ptrs.len() {
            ptrs[i] = unsafe { shenango::ffi::smalloc(SIZE) };
            assert!(!ptrs[i].is_null());
        }

        for i in 0..ptrs.len() {
            unsafe { shenango::ffi::sfree(ptrs[i]) };
        }
    }
}


fn main() {
    let mut tsc;
    let mut tsc_elapsed;

    shenango::base_init().unwrap();
    shenango::base_init_thread().unwrap();

    let mut ptrs = vec![ptr::null_mut(); N];

    println!("testing BASE smalloc performance");

    let mut i = 1;
    while i <= N {
        shenango::cpu_serialize();
        tsc = shenango::rdtsc();

        smalloc_bench(SAMPLES, &mut ptrs[..i]);

        tsc_elapsed = shenango::rdtscp().0 - tsc;
        println!(
            "smalloc {} took: {} cycles / allocation",
            i,
            tsc_elapsed / (SAMPLES * i as u32) as u64
        );

        i *= 2;
    }

    println!("testing BASE smalloc performance (warmed up)");

    let mut i = 1;
    while i <= N {
        shenango::cpu_serialize();
        tsc = shenango::rdtsc();

        smalloc_bench(SAMPLES, &mut ptrs[..i]);

        tsc_elapsed = shenango::rdtscp().0 - tsc;
        println!(
            "smalloc {} took: {} cycles / allocation",
            i,
            tsc_elapsed / (SAMPLES * i as u32) as u64
        );

        i *= 2;
    }


    println!("testing GLIBC malloc performance");

    let mut i = 1;
    while i <= N {
        shenango::cpu_serialize();
        tsc = shenango::rdtsc();

        malloc_bench(SAMPLES, &mut ptrs[..i]);

        tsc_elapsed = shenango::rdtscp().0 - tsc;
        println!(
            "malloc {} took: {} cycles / allocation",
            i,
            tsc_elapsed / (SAMPLES * i as u32) as u64,
        );

        i *= 2;
    }

    println!("testing GLIBC malloc performance (warmed up)");

    let mut i = 1;
    while i <= N {
        shenango::cpu_serialize();
        tsc = shenango::rdtsc();

        malloc_bench(SAMPLES, &mut ptrs[..i]);

        tsc_elapsed = shenango::rdtscp().0 - tsc;
        println!(
            "malloc {} took: {} cycles / allocation",
            i,
            tsc_elapsed / (SAMPLES * i as u32) as u64,
        );

        i *= 2;
    }
}
