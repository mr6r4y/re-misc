#include <stdio.h>

void init(int argc, char **argv, char **envp)
{
    printf("%s\n", __FUNCTION__);
}


__attribute__((section(".init_array"))) typeof(init) *__init = init;


int main()
{

}