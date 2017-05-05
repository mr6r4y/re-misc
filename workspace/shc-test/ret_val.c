struct s
{
	int a;
	int b;
	int c;
};

struct s get_some_values (int a)
{
	return (struct s){.a=a+1, .b=a+2, .c=a+3};
};

void main()
{
	struct s a;

	a = get_some_values(7);
}