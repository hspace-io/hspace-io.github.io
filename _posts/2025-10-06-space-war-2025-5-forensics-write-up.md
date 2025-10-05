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
![image.png](../assets/img/2025_spacewar5/Flag_Flax/1.png)

파일시스템 내부에는 flag파일이 1개 존재하고 flag의 내용은 다음과 같습니다.
![image.png](../assets/img/2025_spacewar5/Flag_Flax/2.png)

ZFS는 CoW(Copy-on-Write) 방식을 채택하고 있어, 데이터가 변경될 때 기존 블록을 덮어쓰지 않고 새로운 블록에 기록한 후 메타데이터를 갱신하는 구조를 가지고 있다. 즉 파일을 삭제하더라도 파일시스템 내에서의 실제 데이터는 삭제되지 않는다. 이러한 특성 덕분에 ZFS는 파일이나 블록의 이전 상태를 유지할 수 있으며, 이를 기반으로 자체적인 스냅샷(Snapshot) 기능을 제공한다.

또한 ZFS는 압축 알고리즘을 지원하며 해당 문제의 이미지는 gzip-9의 압축 알고리즘을 이용하여 파일을 압축하고 있어, raw파일에서는 flag에 평문으로 접근할 수 없습니다. zdb는 ZFS 내부 메타데이터 구조를 로우 레벨에서 조사할 수 있는 도구입니다. 이를 이용하여ZFS의 내부 메타데이터 등을 살펴볼 수 있습니다.
![image.png](../assets/img/2025_spacewar5/Flag_대신_Flax/3.png)

ZFS 내부에 hspace명의 스냅샷이 있는 것을 확인할 수 있습니다.
![image.png](../assets/img/2025_spacewar5/Flag_Flax/4.png)

zfs clone ctf@hspace ctf/hspace 를 통해 삭제된 flag를 찾을 수 있습니다.
![image.png](../assets/img/2025_spacewar5/Flag_Flax/5.png)

FLAG: HSPACE{z3774by73_fi13_5y573m_zz4n6}

## Insider's_Shadow


## Pick Me !

## Stealth Signal

## Can you recovery SQLite?-?

## Missing_Key

## 내 파일이... 안돼...

## HERE I AM
