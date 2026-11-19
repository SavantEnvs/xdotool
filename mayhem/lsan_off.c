/* Disable LeakSanitizer at build time (SPEC §6.2 item 15). Xlib/libxdo allocate
 * per-connection state that is never freed before exit; leaks are not this fleet's bug class. */
int __lsan_is_turned_off(void);
int __lsan_is_turned_off(void) { return 1; }
