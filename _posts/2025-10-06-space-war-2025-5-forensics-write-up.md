---
title: 2025 SpaceWar#6 (FORENSICS) 풀이
description: HSPACE에서 출제한 2025 SpaceWar 포렌식 문제 풀이입니다.
author: LEEJINUNG
date: 2025-07-26 19:00:00 +0900
tags: [Tech, CTF]
categories: [Tech, CTF, FORENSICS]
math: true
mermaid: false
pin: false
image: /assets/img/2025_spacewar5/thumbnail.jpg
---

## 목차

- [목차](#목차)
- [Flag 대신 Flax?](#Flag_대신_Flax?)
- [Insider's Shadow](#Insider's_Shadow)
- [Pick Me !](#Pick Me !)
- [Stealth Signal](#Stealth Signal)
- [Can you recovery SQLite?-?](#Can you recovery SQLite?-?)
- [Missing_Key](#Missing_Key)
- [내 파일이... 안돼...](#내 파일이... 안돼...)
- [HERE I AM](#HERE I AM)

## Flag_대신_Flax?

해당 문제는 ZFS 파일시스템의 구조와 기능을 활용하여 삭제된FLAG 파일을 복원하는 문제입니다.
ZFS는 Copy-on-Write(COW) 방식을 채택하고 있어, 파일을 삭제하더라도 기존 데이터 블록이 즉시 제거되지 않고 파일시스템 내에 남아 있게 됩니다. 이러한 특성 덕분에 ZFS는 자체적으로 스냅샷(Snapshot) 기능을 지원합니다.

문제에 제공된 img파일은 ZFS으로 ubuntu 등 리눅스 시스템ZFS 패키지 설치 후 zpool import로 마운트할 수 있습니다.
![image.png](../assets/img/2025_spacewar5/FLAG_FLEX/1.png)

파일시스템 내부에는 flag파일이 1개 존재하고 flag의 내용은 다음과 같습니다.
![image.png](../assets/img/2025_spacewar5/FLAG_FLEX/2.png)

ZFS는 CoW(Copy-on-Write) 방식을 채택하고 있어, 데이터가 변경될 때 기존 블록을 덮어쓰지 않고 새로운 블록에 기록한 후 메타데이터를 갱신하는 구조를 가지고 있다. 즉 파일을 삭제하더라도 파일시스템 내에서의 실제 데이터는 삭제되지 않는다. 이러한 특성 덕분에 ZFS는 파일이나 블록의 이전 상태를 유지할 수 있으며, 이를 기반으로 자체적인 스냅샷(Snapshot) 기능을 제공한다.

또한 ZFS는 압축 알고리즘을 지원하며 해당 문제의 이미지는 gzip-9의 압축 알고리즘을 이용하여 파일을 압축하고 있어, raw파일에서는 flag에 평문으로 접근할 수 없습니다. zdb는 ZFS 내부 메타데이터 구조를 로우 레벨에서 조사할 수 있는 도구입니다. 이를 이용하여ZFS의 내부 메타데이터 등을 살펴볼 수 있습니다.<br>
![image.png](../assets/img/2025_spacewar5/FLAG_FLEX/3.png)

ZFS 내부에 hspace명의 스냅샷이 있는 것을 확인할 수 있습니다.
![image.png](../assets/img/2025_spacewar5/FLAG_FLEX/4.png)

zfs clone ctf@hspace ctf/hspace 를 통해 삭제된 flag를 찾을 수 있습니다.
![image.png](../assets/img/2025_spacewar5/FLAG_FLEX/5.png)

FLAG: HSPACE{z3774by73_fi13_5y573m_zz4n6}

## Insider's_Shadow

문제로는 하이브 파일 5개가 주어집니다.
![image.png](../assets/img/2025_spacewar5/Insider_Shadow/1.png)

이 문제는 김영수 직원이 비정상적인 네트워크 연결을 통해 데이터를 전송했는지 조사하는 것으로, 레지스트리에서 네트워크 연결 기록을 분석해야 한다. REGA로 주어진 하이브 파일을 열면 다음과 같이 확인할 수 있습니다.
![image.png](../assets/img/2025_spacewar5/Insider_Shadow/2.png)

네트워트 연결 기록은 다음 레지스트리에 저장됩니다.
| 레지스트리 경로 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` |
|------|-----|

다음 경로로 이동하여 확인하면, 3개의 네트워크 연결 기록을 확인할 수 있으며, 각각 네트워크 이름, 최초 연결 시간, 마지막 연결 시각들을 확인할 수 있습니다.
![image.png](../assets/img/2025_spacewar5/Insider_Shadow/3.png)

사내에서 허용된 네트워크는 "forensics.lab"으로, 해당 네트워크는 “2025년 5월 9일 금요일 16:24:41”에 최초 연결되어 “2025년 9월 23일 화요일 23:02:59” 최근까지 정상적으로 이용되고 있었습니다.
![image.png](../assets/img/2025_spacewar5/Insider_Shadow/4.png)

네트워크 연결 기록을 분석한 결과, "Eden_iPhone"이라는 외부 네트워크 연결을 발견했습니다. 해당 네트워크는 2025년 9월 23일 22:35:04에 최초 연결된 것을 확인할 수 있으며, 이는 회사 내부에서 개인 iPhone 핫스팟으로 연결한 기록으로, 승인되지 않은 비정상적인 네트워크 연결에 해당합니다.
![image.png](../assets/img/2025_spacewar5/Insider_Shadow/5.png)

## Pick Me !

## Stealth Signal

## Can you recovery SQLite?-?

## Missing_Key

## 내 파일이... 안돼...

## HERE I AM
