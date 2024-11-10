#include <string.h>
#include <stdio.h>
#include <unistd.h>

void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}

int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";
    setbuf(stdout, buf);
    int len = strlen(buf);
    write(1, buf, len);
    vuln();
    return 0;
};