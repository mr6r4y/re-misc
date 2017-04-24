all: empty_main empty_main_pic empty_main_gdb init_array hook start_nostdlib t.bin hook_pic hook_pic_x86 hook_x86 scan_x86 scan strcpy_crash strcpy_crash_x86

empty_main: empty_main.c
	gcc -o $@ $^

empty_main_pic: empty_main.c
	gcc -fPIC -o $@ $^

empty_main_gdb: empty_main.c
	gcc -ggdb -o $@ $^

init_array: init_array.c
	gcc -o $@ $^

hook: hook.c
	gcc -o $@ $^

hook_pic: hook.c
	gcc -fPIC -o $@ $^

hook_pic_x86: hook.c
	gcc -m32 -fPIC -o $@ $^

hook_x86: hook.c
	gcc -m32 -o $@ $^

start_nostdlib: start_nostdlib.c
	gcc -nostdlib -o $@ $^
	strip $@

scan_x86: scan.c
	gcc -m32 -o $@ $^

scan: scan.c
	gcc -o $@ $^

strcpy_crash_x86: strcpy_crash.c
	gcc -m32 -o $@ $^

strcpy_crash: strcpy_crash.c
	gcc -o $@ $^

t.bin: t.rasm
	rasm2 -Bf t.rasm -O t.bin

clean:
	rm empty_main empty_main_pic empty_main_gdb init_array hook start_nostdlib t.bin hook_pic hook_pic_x86 hook_x86 scan_x86 scan strcpy_crash strcpy_crash_x86


.PHONY: clean all
