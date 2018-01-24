#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
	if (argc == 4 && !strcmp("XbinXls", argv[0]) && !strcmp("-l", argv[1]) && !strcmp("foo", argv[2]) && !strcmp("bar", argv[3]))
		while (true);
  return EXIT_SUCCESS;
}
