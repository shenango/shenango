#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![feature(asm)]

use std::os::raw::{c_int, c_void};
use std::{mem, panic};

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
pub fn base_init_thread() -> Result<(), i32> {
    convert_error(unsafe { ffi::base_init_thread() })
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
    unsafe { asm!("rdtsc" : "={eax}"(a), "={edx}"(d) : : : "volatile" ) };
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
    unsafe { asm!("cpuid" : : : "rax", "rbx", "rcx", "rdx": "volatile") }
}


pub fn microtime() -> u64 {
    unsafe { (rdtsc() - ffi::start_tsc as u64) / ffi::cycles_per_us as u64 }
}

extern "C" fn trampoline<F>(arg: *mut c_void)
where
    F: FnOnce(),
    F: Send + 'static,
{
    let f = arg as *mut F;
    let f: F = unsafe { mem::transmute_copy(&*f as &F) };
    let _result = panic::catch_unwind(panic::AssertUnwindSafe(move || f()));
}

extern "C" fn box_trampoline<F>(arg: *mut c_void)
where
    F: FnOnce(),
    F: Send + 'static,
{
    let f = unsafe { Box::from_raw(arg as *mut F) };
    let _result = panic::catch_unwind(panic::AssertUnwindSafe(move || f()));
}

pub fn thread_spawn<F>(mut f: F)
where
    F: FnOnce(),
    F: Send + 'static,
{
    let mut buf: *mut F = ::std::ptr::null_mut();
    let th = unsafe {
        ffi::thread_create_with_buf(
            Some(trampoline::<F>),
            &mut buf as *mut *mut F as *mut *mut c_void,
            mem::size_of::<F>(),
        )
    };
    assert!(!th.is_null());
    assert!(!buf.is_null());
    unsafe {
        ffi::memcpy(
            buf as *mut c_void,
            &mut f as *mut F as *mut c_void,
            mem::size_of::<F>(),
        );
        mem::forget(f);
        ffi::thread_ready(th)
    };
}

pub fn runtime_init<F>(f: F, ncores: u32) -> Result<(), i32>
where
    F: FnOnce(),
    F: Send + 'static,
{
    convert_error(unsafe {
        ffi::runtime_init(
            Some(box_trampoline::<F>),
            Box::into_raw(Box::new(f)) as *mut c_void,
            ncores,
        )
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
