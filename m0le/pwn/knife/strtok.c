#include <string.h>

void main() {
    char s[]= "abcdefghijklmn";
    char *t = strtok(s, "e");
    t = NULL;
    t = strtok(NULL, "");
    puts(t);
    puts(s);
}
