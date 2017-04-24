#include <stdio.h>

int y;

int z = 10;

int main()
{
	int x;

	printf ("Enter X:\n");
	scanf ("%d", &x);
	printf ("You entered %d...\n", x);

    printf ("Enter X:\n");
    scanf ("%d", &y);
    printf ("You entered %d...\n", y);

    printf ("Enter X:\n");
    scanf ("%d", &z);
    printf ("You entered %d...\n", z);

	return 0;
};
