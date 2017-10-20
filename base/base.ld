SECTIONS
{
  __initcall : {
    . = ALIGN(16);
    __initcall0_start = .;
    KEEP(*(.initcall0))
    __initcall0_end = .;
    __initcall1_start = .;
    KEEP(*(.initcall1))
    __initcall1_end = .;
    __initcall2_start = .;
    KEEP(*(.initcall2))
    __initcall2_end = .;
    __initcallt_start = .;
    KEEP(*(.initcallt))
    __initcallt_end = .;
  }

  __perthread_load = .;
  .perthread 0 : AT(__perthread_load) {
    PROVIDE(__perthread_start = .);
    *(.perthread)
    PROVIDE(__perthread_end = .);
  }
  . = __perthread_load + SIZEOF(.perthread);
}
INSERT AFTER .text
