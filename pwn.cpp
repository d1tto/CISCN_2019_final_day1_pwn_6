//g++ pwn.cpp -o pwn
#include<iostream>
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
using namespace std;
char *chunk_ptr[50];
void do_init()
{
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
}
void my_read(char *ptr,unsigned int size)
{
    read(0,ptr,size);
}
void add()
{
    unsigned int size;
    unsigned int index;
    cout<<"input the index"<<endl;
    cin>>index;
    if(chunk_ptr[index]!=0||index>24)
    {
        exit(0);
    }
    cout<<"input the size"<<endl;
    cin>>size;
    if(size<=0x78)
    {
        chunk_ptr[index]=(char *)malloc(size);
        cout<<"now you can write something"<<endl;
        my_read(chunk_ptr[index],size);
        puts("OK!");
        printf("gift :%p\n",chunk_ptr[index]);
    }
}
void remove()
{
    unsigned int index;
    cout<<"input the index"<<endl;
    cin>>index;
    if(index>24)
        exit(0);
    free(chunk_ptr[index]);
}
void menu()
{
    puts("1. add");
    puts("2. remove");
}
int main()
{
    do_init();	
    cout<<"welcome to babyheap"<<endl;
    unsigned int idx;
    while(1)
    {
        menu();
        cout<<"choice > ";
        cin>>idx;
        switch(idx)
        {
            case 1:add();break;
            case 2:remove();break;
        }
    }
}
