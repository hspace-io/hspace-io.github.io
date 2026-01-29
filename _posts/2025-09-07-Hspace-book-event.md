---
title: "리눅스 서버 모의 해킹을 통해 얻은 보안적 인사이트"
description: "『모의 해킹으로 알아보는 리눅스 서버 해킹과 보안』을 기반으로 서버 환경을 재현하며, 단순 취약점 실습을 넘어 실무적 보안 교훈을 도출한 기록"
author: 고희권
date: 2025-09-06 21:00:00 +0900
tags: [linux, serversecurity, penetrationtesting, insight, defense]
categories: [Blue Team & Defense, Detection Engineering]
comments: false
math: false
mermaid: true
pin: false
---

## 1. 배경 (Why)
리눅스 서버는 웹 서비스, 데이터베이스, 메일 서버 등 현대 IT 인프라의 핵심을 이루는 운영 환경이다. 대규모 기업뿐 아니라 스타트업, 공공기관, 심지어 개인 개발자의 서비스까지 리눅스 서버 위에서 구동되고 있으며, 따라서 해당 환경의 보안은 곧 서비스의 안정성과 직결된다.

최근 사이버 공격 양상은 단순한 웹 취약점 탐색을 넘어 서버 내부로 침투하여 시스템 권한을 확보하고, 데이터베이스를 탈취하거나 서비스 거부 상태를 유발하는 등 점점 정교해지고 있다. 공격자의 관점에서 리눅스 서버를 이해하고, 실제로 어떤 공격 기법이 가능한지 배우는 것은 필수적이다.

『모의 해킹으로 알아보는 리눅스 서버 해킹과 보안』은 리눅스 서버 보안을 실습 기반으로 다루는 교재로, 공격 환경과 방어 환경을 직접 구축하고 공격을 재현한 뒤 대응책까지 실습할 수 있도록 구성되어 있다. 본 보고서는 단순히 “해킹이 가능하다”라는 사실을 기록하는 것이 아니라, 운영자가 반드시 인식해야 할 보안적 교훈을 정리하고, 이를 실무 환경에서 적용할 수 있는 방법을 탐구하는 데 중점을 두었다.

## 2. 실습 환경 구축 및 리눅스 서버 관리 기본 명령어 정리

### 2.1 실습 환경 구축
- 호스트 운영체제: Windows 11
- 가상화 툴: VirtualBox
- 서버: Ubuntu 20.04 LTS
- 공격자 환경: Kali Linux 2023

서버와 공격 환경을 독립적으로 구성하여 실습 중 발생할 수 있는 시스템 오류나 공격 코드 실행으로부터 호스트 OS를 보호하였다.

### 2.2 리눅스 서버 관리 기본 명령어

| 명령어 | 설명 | 활용 예시 및 보안적 시사점 |
|--------|------|----------------------------|
| `ls`, `ls -al` | 현재 디렉토리 파일 목록 조회 | 숨김 파일(.ssh, .config) 확인 시 계정 보안 점검 가능 |
| `pwd` | 현재 작업 디렉토리 출력 | 경로 기반 권한 확인 |
| `cd` | 디렉토리 이동 | 루트 디렉토리 접근 가능 여부 점검 |
| `cat`, `less` | 파일 내용 확인 | `/etc/passwd`로 계정 정보 노출 위험 확인 |
| `cp`, `mv`, `rm` | 파일 복사/이동/삭제 | 로그 파일 위·변조 시도 탐지에 중요 |
| `chmod`, `chown` | 권한 및 소유자 변경 | 잘못된 권한 설정은 취약점으로 직결 |
| `ps aux`, `top` | 실행 중인 프로세스 확인 | 의심스러운 백도어 프로세스 탐지 가능 |
| `netstat -tulnp`, `ss -tulnp` | 네트워크 포트 및 연결 상태 확인 | 비정상 포트 개방 여부 파악 |
| `ifconfig`, `ip addr` | 네트워크 인터페이스 정보 조회 | 공격 시 외부 IP 노출 여부 확인 |
| `tail -f /var/log/syslog` | 로그 실시간 모니터링 | 침입 흔적 추적 및 관리자 경고 설정 활용 |
| `find / -name [파일명]` | 파일 검색 | 악성 파일 은닉 여부 점검 |
| `grep [패턴] [파일]` | 텍스트 검색 | 대규모 로그에서 공격 흔적 신속 탐색 |

## 3. 리눅스 서버 주요 보안 설정

### 3.1 부트로더 보안 (GRUB 패스워드 설정)
- 리눅스 부팅 시 GRUB 부트로더에서 커널을 선택한다.
- 공격자가 서버에 물리적으로 접근하면 싱글 모드나 `init=/bin/bash` 지정으로 관리자 권한 탈취 가능.

**설정 절차**
```bash
grub-mkpasswd-pbkdf2  # 비밀번호 입력 후 Hash 출력
```
- `/etc/grub.d/40_custom` 파일에 추가:
```
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.[...]
```
- 적용: `update-grub`

**보안적 시사점**
부트로더 단계에서 비밀번호를 걸면 서버 물리 접근자가 관리자 권한을 무단으로 획득하는 위험을 줄일 수 있음.

### 3.2 사용자 계정 관리
- 불필요한 계정, 기본 계정, 과도한 권한 계정은 공격자의 표적
- 계정 관리 명령어 예시:
```bash
adduser testuser
passwd testuser
userdel -r olduser
usermod -aG sudo testuser
id testuser
```
**보안적 시사점**
- 불필요한 계정 삭제
- 관리자 계정 최소화
- root 계정 직접 사용 지양, sudo 사용 권장

### 3.3 방화벽 설정 (UFW, iptables)
- Ubuntu: UFW / CentOS: firewalld, iptables
- 기본 명령어:
```bash
ufw status
ufw enable
ufw allow 22/tcp
ufw deny 23/tcp
```
**보안적 시사점**
- 최소 허용 원칙 적용: 꼭 필요한 포트만 개방
- 불필요한 포트는 공격 경로가 됨

### 3.4 PAM(Pluggable Authentication Modules) 활용
- 비밀번호 정책 강화, 로그인 실패 제한, 계정 잠금 가능
- 예시 설정:
```bash
# /etc/pam.d/common-password
password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1

# /etc/pam.d/common-auth
auth required pam_tally2.so deny=5 unlock_time=600
```
**보안적 시사점**
- Brute Force 공격 방어
- 서버 보안 정책 수립 시 필수

## 4. 웹 보안(Web Security) 기술명세서

### 4.1 웹 서버 취약점 점검 및 대응
- Apache 디렉토리 리스팅 점검: `http://localhost/test/` #로컬호스트는 이렇게 부르겠습니다.
- 대응 조치:
```apache
<Directory /var/www/>
    Options -Indexes
</Directory>
```
**보안적 의미**
- 서버 기본 설정 점검과 불필요 계정 제거 필수
- 단순 설정 오류도 정보 유출 위험

### 4.2 웹 어플리케이션 취약점 실습
- SQL Injection, XSS, CSRF 테스트 및 방어
```python
# SQL Injection 방어 예시 (Prepared Statement)
cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
```
- XSS: 입력값 필터링 및 HTML 이스케이프
- CSRF: CSRF 토큰 검증, SameSite 쿠키 설정

### 4.3 웹 로그 분석
- Apache 접근 로그, 인증 로그, 어플리케이션 로그 모니터링
```bash
tail -f /var/log/apache2/access.log
cat /var/log/auth.log | grep "Failed password"
```
**보안적 의미**
- 정기적 로그 분석으로 공격 패턴 확인
- SIEM 연계로 실시간 탐지 가능
- 사전 예방과 사후 대응 모두 효과적

### 4.4 종합적 보안 관리
- 웹 서버 설정 점검 + 어플리케이션 취약점 방어 + 로그 분석 통합 운영
- 정기적 패치, 보안 코딩, 계정 관리, 로그 모니터링 필수
- 실습을 통해 설정 오류와 코드 취약점을 검증하여 실제 서버 사고 최소화

## 5. 마치며
- 단순한 설정 하나와 코드 취약점이 큰 보안 위협이 될 수 있음을 실습으로 체감
- 로그 분석과 실시간 모니터링은 사전 예방과 사후 대응 모두 필수
- 통합적 보안 관리가 실제 서버 운영에서 사고를 최소화하는 핵심임을 인식