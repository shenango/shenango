#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![feature(asm)]

use std::os::raw::{c_int, c_uint, c_void};

pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn convert_error(ret: c_int) -> Result<(), i32> {
    if ret == 0 {
        Ok(())
    } else {
        Err(ret as i32)
    }
}

pub fn base_init() -> Result<(), i32> {
    convert_error(unsafe { ffi::base_init() })
}
pub fn base_init_thread(cpu: u32) -> Result<(), i32> {
    convert_error(unsafe { ffi::base_init_thread(cpu as c_uint) })
}

pub fn delay_us(microseconds: u64) {
    unsafe { ffi::__time_delay_us(microseconds) }
}
pub fn thread_yield() {
    unsafe { ffi::thread_yield() }
}

pub fn rdtsc() -> u64 {
    let a: u32;
    let d: u32;
    unsafe { asm!("rdtsc" : "={eax}"(a), "={edx}"(d) : : : "volatile" )};
    (a as u64) | ((d as u64) << 32)
}
pub fn rdtscp() -> (u64, u32) {
    let a: u32;
    let d: u32;
    let c: u32;
	unsafe { asm!("rdtscp" : "={eax}"(a), "={edx}"(d), "={ecx}"(c) : : : "volatile") };

	((a as u64) | ((d as u64) << 32), c)
}
pub fn cpu_serialize() {
	unsafe {asm!("cpuid" : : : "rax", "rbx", "rcx", "rdx": "volatile") }
}


pub fn microtime() -> u64 {
    unsafe { (rdtsc() - ffi::start_tsc as u64) / ffi::cycles_per_us as u64 }
}

pub type ThreadSpawnFn = unsafe extern "C" fn(arg: *mut c_void);
pub fn thread_spawn<T: Sync>(f: ThreadSpawnFn, arg: &T) -> Result<(), i32> {
    convert_error(unsafe { ffi::thread_spawn(Some(f), &*arg as *const T as *mut c_void) })
}
pub fn runtime_init<T: Sync>(f: ThreadSpawnFn, arg: *const T, ncores: u32) -> Result<(), i32> {
    convert_error(unsafe {
        ffi::runtime_init(Some(f), arg as *mut c_void, ncores)
    })
}

pub struct WaitGroup {
    inner: ffi::waitgroup,
}
impl WaitGroup {
    pub fn new() -> Self {
        let mut inner: ffi::waitgroup = unsafe { std::mem::uninitialized() };
        unsafe { ffi::waitgroup_init(&mut inner as *mut _) };
        Self { inner }
    }
    pub fn add(&self, count: i32) {
        unsafe { ffi::waitgroup_add(&self.inner as *const _ as *mut _, count as c_int) }
    }
    pub fn wait(&self) {
        unsafe { ffi::waitgroup_wait(&self.inner as *const _ as *mut _) }
    }
    pub fn done(&self) {
        self.add(-1)
    }
}
unsafe impl Send for WaitGroup {}
unsafe impl Sync for WaitGroup {}
