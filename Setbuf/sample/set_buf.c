#include<stdio.h>

int main(){

char buf[10];
memset(buf,0,10);
buf[0] = '1';
printf(buf);
setbuf(stdout,buf);
printf("testme.");
return 0;
}
