/* URL: https://challenges.re/53/
 * This code, compiled in Linux x86-64 using GCC is crashing while execution (segmentation fault). 
 * It's also crashed if compiled by MinGW for win32. However, it works in Windows environment if compiled by MSVC 2010 x86. Why?
 *
 * Cause "Hello, world!\n" is in .rodata segment which is raad-only in Linux
 */


#include <string.h>
#include <stdio.h>

void alter_string(char *s)
{
        strcpy (s, "Goodbye!");
        printf ("Result: %s\n", s);
};

int main()
{
        alter_string ("Hello, world!\n");
};