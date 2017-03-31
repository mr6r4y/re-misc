#!/bin/bash

gcc -o empty_main empty_main.c
gcc -fpic -o empty_main_pic empty_main.c
gcc -ggdb -o empty_main_gdb empty_main.c
# gcc -nodefaultlibs bempty_main_nodefaultlibs empty_main.c
gcc -o init_array init_array.c
gcc -o hook hook.c

gcc -nostdlib -o start_nostdlib start_nostdlib.c
strip start_nostdlib
