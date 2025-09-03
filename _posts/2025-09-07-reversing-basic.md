---
title: "『리버싱 핵심 원리』1부: OllyDbg를 이용한 abex' crackme #1 분석"
description: " 여름 방학 동안『리버싱 핵심 원리』 책 1부를 읽은 후, OllyDbg를 이용한 abex' crackme #1 실습 경험을 공유합니다."
author: hyeroro
date: 2025-09-07 22:00:00 +0900 # YYYY-MM-DD HH:MM:SS +TZ
tags: [Reverse Engineering, Debugging, CrackMe, OllyDbg]   # 3~5개 소문자·공백X
categories: [Reverse Engineering, Debugging]  # [대분류, 소분류]
comments: false
math: true # Katex, Latex 사용시 true
mermaid: false # 시퀀스·플로우 차트 필요 시 true
pin: false # 메인 화면 상단 고정 여부
image:  # 썸네일 이미지 경로(공란)
---

# **『리버싱 핵심 원리』 1부: OllyDbg를 이용한 abex' crackme #1 분석**

## **목차**

- [학습 배경](#학습-배경)
- [목표 및 진행 상황](#목표-및-진행-상황)
- [디버깅이란?](#디버깅이란)
- [OllyDbg와의 첫 만남](#ollydbg와의-첫-만남)
- [abex' crackme #1 도전기](#abex-crackme-1-도전기)
  - [목표](#목표)
  - [문제](#문제)
  - [실행](#실행)
  - [1. EP(Entry Point) 확인하기](#1-epentry-point-확인하기)
  - [2. 코드 분석하기](#2-코드-분석하기)
  - [3. 풀이](#3-풀이)
    - [방법1: 단순 패치](#방법1-단순-패치)
    - [방법2: ZF 값 변경](#방법2-zf-값-변경)
    - [방법3: EAX 값 변경](#방법3-eax-값-변경)
- [결과](#결과)
- [인사이트](#인사이트)
- [레퍼런스](#레퍼런스)


안녕하세요! HDFLAB 소속 김혜지입니다.
HSPACE 책선물 이벤트에 당첨되어 『리버싱 핵심 원리』책을 수령하였는데요.
이를 통해 여름방학 동안 학습한 내용을 공유하고자 합니다.



## **학습 배경**
HDFLAB의 생산팟에서 활동하며 침해사고 이미지를 직접 제작하는 경험을 하게 되었습니다. 그 과정에서 현실감 있는 시나리오를 만들기 위해 **악성코드 동작을 재현**해야 하는 상황에 직면했습니다. 하지만 당시의 저는 악성코드 분석은커녕 디버거조차 다뤄본 적이 없었기에, 다른 팀원의 분석 과정을 지켜볼 수밖에 없었습니다. 이때 리버싱 공부의 필요성을 절실히 느꼈습니다.

**코드 내부에서 어떤 로직이 실행되는지, 그 결과로 어떤 영향을 미치는지 파악**하는 능력을 키워야겠다는 생각이 들었습니다. 악성코드 분석을 위해서는 실행 파일이나 메모리 덤프에 대한 **정적·동적 분석**이 필수적이고, 이는 곧 리버싱 능력과 직결됩니다. 무엇보다 리버싱은 침해사고 포렌식에도 연관성이 있는 기술이기에 이번 기회에 확실히 짚고 넘어가고자 했습니다. 그 출발점으로 『리버싱 핵심 원리』 책을 선택했습니다.



## **목표 및 진행 상황**
1,030쪽의 엄청난 두께의 책입니다. 따라서 방학 기간 동안의 일회성 공부가 아닌, 장기적인 계획을 세웠습니다. 여름방학 중에는 리버싱의 기본 개념을 이해하고, 단순한 crackme 문제를 스스로 분석할 수 있는 수준까지 도달고자하는 목표를 세웠습니다.

이를 달성하기 위해, 7월에는 리버싱의 기초 개념과 디버거 사용법을 익혔습니다. 8월에는 abex' crackme #1과 #2를 분석하며 실제 코드 흐름과 스택 동작을 체험했습니다. 미래에는 이를 바탕으로 PE 파일 구조 등을 학습한 후 악성코드 샘플을 분석해보고 싶습니다.

이번 글에서는 『리버싱 핵심 원리』책 1부에 해당하는 OllyDbg 사용법과 abex' crackme #1 풀이 경험과 인사이트를 공유하고자 합니다. OllyDbg를 활용하여 abex' crackme #1을 분석하면서 스택 구조, 함수 호출, 레지스터 변화 등을 체험하고 이해한 과정을 소개합니다.



## **디버깅이란?**
리버싱(Reversing)의 큰 축은 정적 분석과 동적 분석으로 나눌 수 있습니다. 정적 분석(Static Analysis) 은 실행하지 않고 코드나 파일 구조를 살펴보는 방식이고, 동적 분석(Dynamic Analysis) 은 프로그램을 실제로 실행시켜 동작을 추적하는 방식입니다. 이때 디버깅(Debugging) 은 동적 분석의 핵심적인 방법 중 하나입니다. 원래 개발자들이 프로그램 오류(버그)를 찾고 수정하기 위해 쓰던 기술이지만, 리버서(역공학자) 입장에서는 오히려 프로그램 내부 동작을 파악하고 숨겨진 로직을 밝혀내는 데 활용됩니다. 디버깅을 통해 코드 흐름과 메모리 상태 등을 자세히 살펴볼 수 있습니다.

- 어떤 함수가 호출되는지
- 레지스터값이 어떻게 변하는지
- 스택 프레임이 어떻게 쌓이고 해제되는지
- 분기문이 어떤 조건에서 갈라지는지
등의 세부 동작을 단계별로 관찰할 수 있습니다.

이 과정을 통해 겉으로는 보이지 않던 프로그램의 내부 구조가 드러나게 되며, CrackMe 문제 풀이나 악성코드 분석에서 “숨겨진 비밀”을 해독하는 열쇠가 됩니다.



## **OllyDbg와의 첫 만남**
제가 처음으로 다룬 디버거는 『리버싱 핵심 원리』책에서 사용하고 있는 OllyDbg입니다. OllyDbg는 무료로 제공되며 직관적인 인터페이스를 갖춘 Windows 기반 32비트 디버거입니다. 가볍고 빠르기 때문에 리버싱 입문자들이 많이 활용하는 도구 중 하나입니다.

아래의 링크에서 다운로드 가능합니다.
http://www.ollydbg.de

OllyDbg를 실행하고 간단히 작성한 HelloWorld.exe 파일을 열어보았습니다.

![image](/assets/img/reversing-basic/reversing1.png)

익숙하지 않은 창들이 많이 떴는데요.
메인 화면은 Code Window, Register Window, Dump Window, Stack Window로 구성되어 있습니다.
Code Window에서는 기본적으로 disassembly code를 표시하여 각종 comment, label을 보여줍니다.
Register Window에서는 CPU register 값을 실시간으로 표시합니다.
Dump Window에서는 프로세스에서 원하는 memory 주소 위치를 Hex와 ASCII/유니코드 값으로 표시합니다.
Stack Window에서는 ESP register가 가리키는 프로세스 stack memory를 실시간으로 표시합니다.

디버거가 멈춘 곳은 EP(Entry Point)인데요. EP란 Windows의 실행 파일의 코드 시작점을 의미합니다. 프로그램이 실행될 때 CPU에 의해 가장 먼저 실행되는 코드 시작 위치라고 생각하면 됩니다.

OllyDbg의 기본 명령어는 다음과 같습니다.
[Ctrl+F2]은 Restart 명령어로, 디버깅 당하는 프로세스를 종료하고 재실행합니다.
[F7]은 Step Into 명령어로, 하나의 OP code(OPeration code, CPU 명령어)를 실행하고 CALL 명령을 만나면 그 함수 코드 내부로 따라 들어갑니다.
[F8]은 Step Over 명령어로, 하나의 OP code를 실행하고 CALL 명령을 따라 들어가지 않습니다.
[Ctrl+F9]는 Execute till Return 명령어로, 함수 코드 내에서 RETN 명령어까지 실행하여 함수를 탈출합니다.

위 명령어들은 HelloWorld.exe 파일을 대상으로 직접 사용해보면서 손에 익혔습니다. 책에 나와 있는 대로 따라가다 보면 어떤 명령어를 어떤 상황에 사용해야 하는지 바로 감을 잡을 수 있습니다.

아래 이미지는 HelloWorld.exe 파일의 Code Window 화면 일부분입니다.

![image](/assets/img/reversing-basic/reversing2.png)

가령, 4011A0과 4011A5 주소의 disassembly code를 보면 40270C 주소의 함수를 호출하고 40104F 주소로 점프합니다. 이때 4011A0 주소에서 Step Into[F7] 명령어를 사용하면 40270C 함수 안으로 따라갈 수 있습니다. 40270C 함수 안에서는 RETN 명령어까지 Step Over[F8] 하거나 Execute till Return[Ctrl+F9] 하여 갈 수 있고, 이후 RETN 명령어를 실행[F7/F8] 하면, 4011A5 주소로 오게 됩니다.

더 자세한 동작 명령어를 포함하여 정리하면 다음과 같습니다.

| 명령어 | 단축키 | 설명 |
|-------|-------|-------|
| Restart | Ctrl+F2 | 디버깅 당하는 프로세스를 종료하고 재실행 |
| Step Into | F7 | 하나의 OP code를 실행하고 CALL 명령을 만나면 그 함수 코드 내부로 따라 들어감 |
| Step Over | F8 | 하나의 OP code를 실행하고 CALL 명령을 따라 들어가지 않음 |
| Execute till Return | Ctrl+F9 | 함수 코드 내에서 RETN 명령어까지 실행하여 함수를 탈출 |
| Go to | Ctrl+G | 원하는 주소로 이동 |
| Execute till Cursor | F4 | cursor 위치까지 실행 |
| Comment | ; | Comment 추가 |
| Label | : | Label 추가 |
| Set/Reset BreakPoint | F2 | BP 설정/해제 |
| Run | F9 | 실행(BP가 있으면 그곳에서 실행 정지) |
| Edit Data | Ctrl+E | 데이터 편집 |
| Assemble | Space | 어셈블리 코드 작성 |



## **abex' crackme #1 도전기**
crackme라는 프로그램은 말 그대로 크랙 연습 목적으로 작성되어 공개된 프로그램입니다. abex' crackme는 초보자들에게 적합한 프로그램이기에 국내뿐만 아니라 해외의 다양한 풀이를 찾아볼 수 있습니다. 저는 책을 통해 따라 익혀보고, 다른 사람들의 풀이를 찾아보는 방식으로 학습했습니다.



### **목표**
crackme 샘플을 분석하여 디버거와 disassembly code에 익숙해지는 것을 목표로 했습니다. 



### **문제**
abex' crackme #1 문제를 비롯한 『리버싱 핵심 원리』책 내부의 실습 예제는 아래 깃헙에서 다운로드 가능합니다.
https://github.com/reversecore/book

또한 abex' crackme #1 문제는 구글링을 통해 다운로드 받을 수 있습니다.



### **실행**
![image](/assets/img/reversing-basic/reversing3.png)

![image](/assets/img/reversing-basic/reversing4.png)

먼저 파일을 실행시켜서 어떤 프로그램인지 살펴보았습니다. 위 이미지와 같이 "Make me think your HD is a CD-Rom." 이라는 메시지 박스가 출력되고, 확인 버튼을 누르면 "Nah... This is not a CD-ROM Drive!"라는 에러 메시지가 출력됩니다.



### **1. EP(Entry Point) 확인하기**
![image](/assets/img/reversing-basic/reversing5.png)

OllyDbg를 실행시켜서 파일의 disassembly code를 확인해보았습니다. 00401000이 실제 EP 주소이며, EP에 main 함수가 바로 나타나는 것을 파악할 수 있습니다. 이제 눈으로 코드를 분석해보겠습니다.



### **2. 코드 분석하기**
![image](/assets/img/reversing-basic/reversing6.png)

위 부분을 Win32 API 함수 호출 위주로 살펴보면 다음과 같습니다. 

MessageBoxA()함수가 "Make me think your HD is a CD-Rom" 라는 텍스트 메시지와 "abex' 1st crackme"라는 caption과 함께 CALL됩니다. 그 후 00401018 주소에서 GetDriveTypeA() 함수가 호출됩니다. GetDriveTypeA() 함수는 드라이브의 종류에 따라 특정 값을 반환합니다.

![image](/assets/img/reversing-basic/reversing7.png)

GetDriveTypeA() 함수 호출 이후의 EAX 레지스터값은 직접 코드 실행을 통해 위와 같이 확인할 수 있습니다. EAX 레지스터값이 3으로 변화했습니다. 3이 어떤 것을 의미하는지 파악하기 위해 마이크로소프트 기술 문서를 확인해보았습니다.


| 반환 코드/값       | 묘사                                                                 |
|---------------------|----------------------------------------------------------------------|
| DRIVE_UNKNOWN (0)   | 드라이브 유형을 확인할 수 없습니다.                                  |
| DRIVE_NO_ROOT_DIR (1) | 루트 경로가 잘못되었습니다. 예를 들어 지정된 경로에 탐재된 볼륨이 없습니다. |
| DRIVE_REMOVABLE (2) | 드라이브에 이동식 미디어가 있습니다. 예를 들어 플로피 드라이브, 썸 드라이브 또는 플래시 카드 판독기입니다. |
| DRIVE_FIXED (3)     | 드라이브에 고정 미디어가 있습니다. 예를 들어 하드 디스크 드라이브 또는 플래시 드라이브입니다. |
| DRIVE_REMOTE (4)    | 드라이브는 원격(네트워크) 드라이브입니다.                           |
| DRIVE_CDROM (5)     | 드라이브는 CD-ROM 드라이브입니다.                                   |
| DRIVE_RAMDISK (6)   | 드라이브가 RAM 디스크입니다.                                       |


C 드라이브를 인식하므로 DRIVE_FIXED 값인 3을 반환함을 알 수 있습니다. CD-ROM일 경우 5를 반환합니다. 

![image](/assets/img/reversing-basic/reversing9.png)

0040101D ~ 00401023 주소를 거치면서 ESI는 숫자가 3 증가하고 EAX는 숫자가 2 감소합니다. 0040101F 주소는 의미없는 garbage 코드입니다.
이후 00401024 에서 EAX(1)와 ESI(2)를 비교하는 CMP 명령어를 지납니다. 두 값이 같으면 ZF(Zero Flag)가 1이 되고 아니면 0이 됩니다. 00401026에서는 JE(Jump if Equal) 명령어를 만나 조건 분기가 발생합니다. ZF가 1이면 해당 메모리 주소(0040103D)로 점프하고, 0이면 바로 아래의 메모리 주소(00401028)로 넘어갑니다.
즉, 두 값이 다른 경우에 에러 MessageBoxA()를 출력하게 됩니다.

이제 여기에서 성공 MessageBoxA()를 어떻게 띄울 수 있을까요?!
"Make me think your HD is a CD-Rom."이라는 문제의 의도를 잘 파악해야 합니다.



### **3. 풀이**
저는 총 3가지 방법으로 풀이했습니다.



#### **✅방법1: 단순 패치**
![image](/assets/img/reversing-basic/reversing10.png)

책에서 제시된 크랙 방법입니다. 00401026 주소의 명령어 JE SHORT 0040103D를 JMP 0040103D 명령어로 변경하는 방법입니다.
해당 명령어 위치에 커서를 누르고 Space를 클릭해서 수정하면 됩니다.



#### **✅방법2: ZF 값 변경**
![image](/assets/img/reversing-basic/reversing11.png)

JE 분기문을 그대로 사용한다고 하면, 
실패와 성공의 분기가 결정되는 지점에 BP를 걸어서 ZF 값을 1로 변경합니다.

![image](/assets/img/reversing-basic/reversing12.png)

그러면 성공 MessageBoxA() 주소로 넘길 수 있습니다. 



#### **✅방법3: EAX 값 변경**
성공 MessageBoxA()를 출력하게 하는 EAX값으로 EAX를 변경하는 방법입니다.
GetDriveTypeA() 함수 호출 이후의 ESI 레지스터값은 00401000이고, EAX 레지스터값은 00000003입니다.

이를 각각 ESI, EAX 이라고 명명하여 방정식을 세워보면,
위의 분석 과정을 통해 'ESI+3 == EAX-2'를 만족해야 성공 메시지를 띄울 수 있다는 사실을 알 수 있습니다.
EAX의 값을 변경할 것이기에, ESI에 00401000을 넣으면,
'ESI + 5 == EAX' 를 만족하게 하는 EAX의 값은 00401005 입니다.

따라서 GetDriveTypeA()를 수행한 이후의 EAX 값을 00401005로 수정하면 분기문을 만족하게 됩니다.

![image](/assets/img/reversing-basic/reversing13.png)

CMP 명령어에 도달했을 때 EAX와 ESI의 값이 같음을 확인할 수 있습니다.

![image](/assets/img/reversing-basic/reversing14.png)

그로 인해 JE 명령어에 도달했을 때 ZF가 1로 변합니다.



## **결과**
- abex' crackme #1 실행 흐름과 조건 분기문 구조 이해
- OllyDbg 도구 사용법 이해
- disassembly code 이해
- Win32 API 함수 호출 시 레지스터값 변화 관찰
- crack 성공

![image](/assets/img/reversing-basic/reversing15.png)



## **인사이트**
『리버싱 핵심 원리』는 독자의 흥미를 이끄는 도입부로 시작합니다. 방대한 분량이지만 술술 읽히며, 리버싱 입문자들에게 적합한 내용으로 구성되어 있습니다. 어셈블리와 디버거를 처음 접하는 저도 어느새 crackme 문제를 따라 풀 정도로 성장하였으니, 이 글을 읽고 있는 분들도 금방 성장하실 수 있으리라 생각합니다. 저자는 누누이 '거창한 사전 준비 같은 건 필요없다'라고 강조합니다. 아직 리버싱에 대해 알고 있는 게 하나도 없더라도, OS 구조도 모르고 C언어도 모르는 사람이어도, 이 책만 있으면 리버싱에 입문할 수 있습니다. 

경험해 보니, 단순히 책 내용만 읽는 것보다 **실습을 통한 이해**가 매우 효과적이었습니다. 애초에 실습하지 않을 수 없는 책이기도 합니다. 특히 디버깅 연습용으로 크랙 문제를 풀어보는 것이 많은 도움이 되었습니다. OllyDbg로 직접 코드 흐름을 추적하면서, 책에서 학습한 스택 구조와 레지스터 개념이 실제 프로그램에 어떻게 활용되는지 체감했습니다. crackme 문제를 하나하나 풀 때마다 disassembly code가 눈에 들어오고 단축키와 명령어가 자연스럽게 습득되었습니다.

저는 앞으로 더 많은 크랙 문제를 풀면서 디버깅 과정을 익히고자 합니다. 또한 Windows의 실행 파일 형태인 PE 파일 구조와 IAT 구조를 공부하며 코드와 데이터가 파일에서 어떻게 저장되고 메모리에서 어떻게 로딩되는지 학습할 것입니다. 비록 OllyDbg는 업데이트가 중단되었지만, WinDbg, Ghidra, IDA 등 다양한 디버깅 및 리버스 엔지니어링 도구를 활용하여 분석 범위를 확장하고자 합니다. 이를 토대로 악성코드 분석 및 침해사고 포렌식 연구 역량을 강화하겠습니다. 이러한 기회를 마련해주신 Hspace에 깊이 감사드립니다.
감사합니다!



### 레퍼런스
이승원. 『리버싱 핵심 원리: 악성 코드 전문가의 리버싱 이야기』. 도서출판 인사이트, 2012.
Microsoft. "GetDriveTypeA function (fileapi.h) - Win32 apps." Microsoft Learn, Microsoft, https://learn.microsoft.com/ko-kr/windows/win32/api/fileapi/nf-fileapi-getdrivetypea. Accessed 3 Sept. 2025.
