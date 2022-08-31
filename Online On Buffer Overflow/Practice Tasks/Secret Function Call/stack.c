#include<stdlib.h>
#include<stdio.h>
#include<string.h>

/* Changing this size will change the layout of the stack
* Instructors can change the value each year, so students
* won't be able to use the solutions from the past.
*/



int secret_function()
{
	printf("Inside secret function\n");
	return 1;
}

int bof(char *str)
{
	char buffer[24];
	
	// the following statement has a buffer overflow problem
	strcpy(buffer, str);
	
	printf("Returning from bof\n");
	
	return 1;
}
int main(int argc, char **argv)
{
	char str[300];
	FILE *badfile;
	
	badfile = fopen("badfile", "r");
	
	if(!badfile)
	{
		perror("Opening badfile");
		exit(1);
	}
	
	int length = fread(str, sizeof(char), 300, badfile);
	bof(str);
	fprintf(stdout, "==== Returned Properly ====\n");
	return 1;
	 
}

