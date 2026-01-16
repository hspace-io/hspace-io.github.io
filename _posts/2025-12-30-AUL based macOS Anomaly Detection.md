---
title: "AUL 기반 macOS 이상 행위 탐지"
description: "macOS의 Apple Unified Log와 Fsevents를 활용한 경량화된 위협 탐지 시스템 구축 과정과 인사이트 공유"
author: 김현진
date: 2025-12-30 00:00:00 +0900
tags: [Blue Team & Defense, macos, aul, elk]
categories: [Blue Team & Defense, Detection Engineering]
comments: false
math: false
mermaid: false
pin: false
image: /assets/img/2025-macker/thumbnail.png
---
## **1. Intro (Project Overview)**

---

안녕하세요 BoB 14기 막내온탑 팀입니다.

최근 macOS 점유율이 급증함에 따라 이를 타겟으로 한 보안 위협도 고도화되고 있습니다. 하지만 macOS의 폐쇄적인 로그 시스템과 부족한 분석 도구로 인해 보안 관제에 어려움이 많은 것이 현실입니다.

본 포스팅에서는 저희 팀이 진행한 **“AUL(Apple Unified Log) 기반 macOS 이상 행위 탐지”** 프로젝트를 소개합니다. 특히 macOS 로그 분석의 최대 난제인 **'데이터 마스킹(`<private>`)'** 문제를 어떻게 기술적으로 극복하고, 경량화된 탐지 시스템 'macker'를 구축했는지 그 과정을 공유하려 합니다.

## **2. macOS 관제와 AUL의 한계**

---

### **2.1. 늘어나는 점유율, 부족한 오픈소스 보안 도구**

![image.png](/assets/img/2025-macker/image.png)

최근 개발자 생태계에서 macOS의 점유율은 30%을 넘어서고 있지만, Windows 환경에 비해 보안 연구나 오픈소스 도구는 상대적으로 부족한 실정입니다. 물론 상용 EDR 솔루션같은 강력한 도구가 존재하지만 이는 도입 비용이 높고 시스템 리소스를 많이 차지한다는 단점이 존재했습니다.

### **2.2. AUL, 강력하지만 불친절한 블랙박스**

macOS는 10.12(Sierra)부터 기존의 텍스트 로그를 대체하는 ULS(Unified Logging System)를 도입했습니다. 이를 통해 수집되는 통합 로그가 바로 **AUL**입니다. AUL은 시스템의 방대한 정보를 담고 있어 포렌식의 '보고'로 불리지만, 보안 모니터링 관점에서는 치명적인 한계가 존재했습니다.

**로그 마스킹(Masking)과 리덕션(Redaction)**

애플의 개인정보 보호 정책 강화로 인해, AUL의 상당수가 `<private>` 태그로 마스킹되거나 아예 기록되지 않는 현상이 발생했습니다. 특히 신규 macOS 버전이 출시될 때마다 개인정보 보호 정책은 더욱 강화되고 있으며, 이에 따라 마스킹되는 데이터의 범위 또한 점차 확대되는 추세입니다. 이는 보안 분석가에게 있어 단순 로그 수집을 넘어, OS 버전별 차이점에 대한 정밀한 비교 분석이 선행되어야 함을 의미합니다.

```bash
2025-12-27 14:44:24.489765+0900 0x22c49    Default     0x0                  25662  0    launchctl: [com.apple.xpc.launchctl:All] launchctl load: <private>
```

위 로그 처럼, launchctl을 통해 실행된 프로세스가 무엇인지 `<private>`태그로 가려져 확인할 수 없었습니다. 

특히 파일 I/O 행위를 추적하려 할 때 어떤 파일이 생성되고, 어떤 I/O 행위를 했는지 AUL만으로는 식별이 불가능했습니다. 단순히 로그만 수집해서 ‘누가’, ‘무엇을’ 했는지 알 수 없는 반쪽짜리 관제가 될 위험이 컸습니다.

## **3. 하이브리드 로그 수집과 고도화된 탐지 로직**

---

저희는 단일 로그 소스의 한계를 극복하기 위해 **AUL + Fsevents를 결합한 하이브리드 아키텍쳐**를 설계했습니다.

### **3.1. log stream과 log show의 상호 보완**

macOS에서 저장되는 로그는 사람이 읽을 수 없어 Apple에서 제공하는 log 명령어를 사용해야합니다. 

그래서 저희는 저장된 로그를 보는 ‘log show’ 명령어와 실시간로 보는 ‘log stream’을 병행하여 사용하였습니다. 

| 구분 | `log show` | `log stream` |
| --- | --- | --- |
| 로그 유형 | 저장된 로그 | 실시간 로그 |
| 분석 시점 | 사후 분석 | 실행 시점 분석 |
| 사용 목적 | 타임라인 재구성, 행위 검증 | 즉각적인 이벤트 관찰 |

따라서 두 개를 병행하여 사용하게 되면 macOS를 사용 중에 agent 설치를 하거나 사후에 사고가 발생하여도 공백기를 최소화 가능합니다.

저희 팀은 분석 과정에서 흥미로운 점을 발견했습니다. 바로 `log stream`과 `log show`의 데이터가 100% 일치하지 않는다는 것입니다.

기술적으로 분석해본 결과, 이는 ULS의 메모리 관리 메커니즘 때문이었습니다. `log stream`은 메모리 버퍼(Ring Buffer)에서 실시간으로 발생하는 이벤트를 캡처하지만, `log show`는 압축되어 디스크(`.tracev3`)에 저장된 데이터를 읽어옵니다. 이 과정에서 Apple의 최적화 정책에 의해 **'Info'나 'Debug' 레벨의 일부 로그가 디스크 저장 시점에 누락(Drop)**되거나, 반대로 부팅 직후와 같이 스트림 연결 전의 로그는 `log show`에서만 확인되는 현상이 발생했습니다.

또한 launchd 프로세스의 경우 log show에서만 로그가 확인되는 특성이 있었으며, 이러한 차이로 인해 log stream과 log show를 함께 사용하여 상호 보완적인 로그 수집을 수행하였습니다.

### **3.2. FSEvents로 파일 시스템 감시**

AUL에서 파일 I/O 행위를 추적할 때, ‘누가’, ‘무엇을’ 했는지 추적하기 어렵다는 문제에 대하여 저희는 FSEvents를 통해 보완 하였습니다.

**FSEvents란?**

macOS의 FSEvents API를 사용하면 파일 및 폴더의 생성, 삭제, 이름 변경 등 파일 시스템 이벤트에 대하여 알림을 받을 수 있습니다.

이벤트 발생 시각, 대상 파일 및 경로, 이벤트 (Created, Renamed, Removed, Modified 등)를 확인할 수 있습니다.

```bash
2025-12-27 15:59:45.859376+0900 0x2e286    Info        0x0                  615    0    filecoordinationd: (Foundation) [com.apple.foundation.filecoordination:claims] Received item move hint with purpose com.apple.desktopservices.copyengine -- **<private> -> <private>** (fileID: 1234)
```

예를 들어 파일 경로가 변경될 경우, AUL 에서는 ‘`<private> -> <private> (fileID: 1234)`’ 와 같이 경로 정보가 마스킹된 로그를 확인할 수 있습니다.

이 때 FSEvents를 함께 수집할 경우 다음 같은 이벤트를 통해 실제 경로 변화를 확인할 수 있습니다.

- Renamed 이벤트
    - 예 : `1234 Users/macne/.Trash/test.zip Renamed;`
    - 파일명 및 경로 변경 시 이벤트 생성, 변경된 경로 확인 가능

AUL의 경우 파일명 변경이나 파일 데이터 수정 같은 파일 단위 변경 행위에 대한 로그가 소극적으로 남는 다는 한계가 있습니다. 이로 인해 해당 영역에서는 FSEvents를 단독으로 활용하는 것만으로도 충분한 가치를 가집니다.

특히 랜섬웨어 (Ransomware)는 파일 암호화 과정에서 파일 내용과 함께 확장자가 변경되는 특징적인 행위 패턴을 보여 FSEvents 의 Modified 및 Renamed 이벤트의 연속적인 발생 등을 통해 탐지할 수 있습니다.

### **3.3. Detection Engineering (Sigma & ATT&CK)**

![image.png](/assets/img/2025-macker/image%201.png)

조사한 로그는 MITRE ATT&CK 프레임워크의 TTPs와 매핑하여 단순 이벤트를 체계적인 행위로 매핑하였습니다. 또한 보안 전문가들이 쉽게 공유 및 수정할 수 있도록 Sigma Rule 포맷으로 표준화했습니다.

```yaml
title: Cron
id: 9385f902-a5a4-4b6c-a14c-14db0fd61c44
description: Detects cron executing a user command matching known path or pattern.
references:
  - https://attack.mitre.org/techniques/T1053/003/
logsource:
  product: macos
  category:
detection:
  selection:
    process: "crontab"
    subsystem: ""
    formatstrings: "(%s) %s (%s)\n"
    eventMessage:
      - "END EDIT"
  condition: selection
author: "Eram"
date: "2025-11-03"
falsepositives:
  - Legitimate scheduled jobs (system or user cron entries) such as backups or maintenance scripts.
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053
  - attack.t1053.003
```

실제 탐지룰은 위와 같이 AUL 포맷에 맞춰서 process, subsystem, formatstrings, eventMessage로 필드가 구성되어있습니다.

단순 행위 매칭은 오탐(False Positive)이 많기 때문에 이를 다음과 같은 고급 룰을 적용하였습니다.

**임계치 기반 탐지(Threshold Rule)**은 단일 이벤트만으로는 악성 여부를 판단하기 모호할 때 사용합니다. 특정 시간(Time Window) 내에 동일한 의심 행위가 설정된 임계값(Threshold) 이상 반복적으로 발생할 경우를 공격으로 간주하여 탐지 정확도를 높이는 방식입니다.

```yaml
title: macOS SSH Brute Force Indicator
id: db225203-55be-4768-950c-1ef33fe118eb
status: experimental
description: Detects SSH authentication failures due to maximum attempts exceeded.
author: HJ
date: 2025-12-27
logsource:
    product: macos
    service: aul # Apple Unified Log
detection:
    selection:
        ProcessImagePath|endswith: 'sshd-session' 
        FormatString: '%.500s' 
        EventMessage|contains: 'error: maximum authentication attempts exceeded for'
    condition: selection
level: medium
tags:
    - attack.credential_access
    - attack.t1110
---
# 상관관계 룰
title: macOS SSH Brute Force Attack (Threshold)
id: threshold-005-ssh-brute-force-correlation
status: experimental
correlation:
    type: event_count
    rules:
        - db225203-55be-4768-950c-1ef33fe118eb
    grouping:
        - host.name
    timespan: 5m
    condition:
        gte: 4
```

위 상관관계 룰은 동일 호스트에서 **5분 이내**에 '최대 인증 시도 횟수 초과(maximum authentication attempts exceeded)' 오류가 4**회 이상** 발생할 경우를 트리거합니다. 이는 단순한 실수에 의한 로그인 실패가 아닌, 무작위 대입 공격(SSH Brute Force) 시도로 판단하여 탐지합니다.

**순차적 탐지(Sequence Rule)**은 공격자가 수행하는 일련의 공격 단계(Kill Chain)를 파악하기 위한 방식입니다. 서로 다른 공격 기술이 시간 순서에 따라 연쇄적으로 발생할 때, 이를 개별 이벤트가 아닌 하나의 '공격 시나리오'로 묶어 탐지함으로써 공격의 맥락(Context)을 파악합니다.

```yaml
title: macOS Infostealer Kill Chain Pattern
id: 0ff10bb2-1b35-4ede-be48-390b2e9bc409
status: experimental
description: Detects a sequence of Discovery, Collection, and Exfiltration activities indicative of an Infostealer within 20 minutes.
author: june0320
date: 2025-12-27
correlation:
    type: temporal
    rules:
        - discovery_rules # Placeholder for Discovery Rule IDs
        - collection_rules # Placeholder for Collection Rule IDs
        - exfiltration_rules # Placeholder for Exfiltration Rule IDs
    grouping:
        - host.name
    timespan: 20m
    ordered: true
aliases:
    discovery_rules:
        tags:
            - attack.discovery
    collection_rules:
        tags:
            - attack.collection
    exfiltration_rules:
        tags:
            - attack.exfiltration
level: critical
tags:
    - attack.discovery
    - attack.collection
    - attack.exfiltration
```

위 룰은 인포스틸러(Infostealer) 유형의 악성코드가 주로 수행하는 **'정보 탐색(Discovery) → 중요 정보 수집(Collection) → 외부 유출(Exfiltration)'**의 행위 흐름을 정의한 것입니다. **20분 이내**에 이 세 가지 단계가 순서대로 발생할 경우, 단발성 이벤트가 아닌 조직적인 정보 탈취 시도로 간주하여 Critical 등급으로 탐지합니다.

결론적으로, 단순 문자열 매칭 방식에 그치지 않고 시간적 흐름과 발생 빈도를 고려한 **고급 상관관계 분석(Correlation Analysis)**을 적용함으로써, 정상 행위를 공격으로 오인하는 오탐(False Positive)을 최소화하고 실제 위협 시나리오에 대한 탐지 신뢰도를 비약적으로 향상시켰습니다.

## **4. 경량화 탐지 도구 “macker”**

---

### **4.1. 도구 구성**

최종적으로 구축한 시스템 macker의 아키텍처는 다음과 같습니다.

![image.png](/assets/img/2025-macker/image%202.png)

최종 구축한 시스템 'macker'는 배포와 운영의 효율성을 위해 **Docker 컨테이너 기반**으로 설계되었습니다.

**Agent**

- Python 기반 수집기 + Filebeat (AUL & FSEvents 수집)
- 단순 수집이 아닌, `log stream`의 실시간성과 `log show`의 데이터 무결성을 실시간으로 교차 검증하여 중복을 제거하고 누락된 로그를 보완하는 핵심 엔진입니다.

**Server**

- Logstash (전처리/파싱) → Elasticsearch (저장/인덱싱)

**Dashboard**

- Kibana Dashboard(시각화) & Python Alert System(알림)

### **4.2. 상세 내용**

**시각화 대시보드**

수집된 데이터를 직관적으로 볼 수 있도록 3가지 뷰를 제공합니다.

- **Overview:** 비전문가도 즉시 대응 가능한 시각화 기반의 통합 대시보드
    
    전체 호스트의 위협 스코어를 히트맵으로 시각화하여, 관제 요원이 출근 직후 가장 먼저 대응해야 할 단말을 직관적으로 식별합니다.
    
    ![image.png](/assets/img/2025-macker/image%203.png)
    
- User-Risk: 고위험군 사용자 타겟팅을 통합 심층 분석 및 공격 행위 추적 대시보드
    
    Section 3에서 정의한 'Threshold' 및 'Sequence' 룰에 기반하여, 단순 실수가 아닌 의도적인 공격 징후를 보이는 사용자를 핀포인트로 분석합니다.
    
    ![image.png](/assets/img/2025-macker/image%204.png)
    
- Fsevent Monitoring: 랜섬웨어 탐지 및 실시간 파일 변경 이력 확인 대시보드
    
    랜섬웨어 공격 시 파일 확장자가 변조되거나 엔트로피가 급증하는 순간을 실시간 그래프로 보여주어, 피해 확산을 막기 위한 근거 데이터를 제공합니다.
    
    ![image.png](/assets/img/2025-macker/image%205.png)
    

**Alert**

Ciritical 이벤트 발생 시 즉시 메일로 전송해주는 Alert 시스템

대시보드를 보고 있지 않더라도 치명적인 위협(Critical)이 탐지되면, Python 자동화 스크립트가 즉시 보안 담당자에게 메일을 발송합니다. 메일에는 **탐지 시간, 룰 이름, 호스트명, 위협 등급**이 상세히 포함되어 신속한 의사결정을 지원합니다

![image.png](/assets/img/2025-macker/image%206.png)

### **4.3. 정량적 평가**

![image.png](/assets/img/2025-macker/image%207.png)

본 시스템의 유효성을 검증하기 위해 실제 악성코드 10종(Ransomware 3종, Infostealer 4종, Dropper 3종)을 대상으로 공격 시나리오를 재현하여 탐지 성능을 측정했습니다.

실험 결과, **정밀도(Precision)는 0.79, 재현율(Recall)은 0.70**을 기록했습니다. 특히 정밀도 0.79는 기존 ML을 사용하지 않은 행위 탐지 연구들의 평균치와 동등한 수준으로, 커널 레벨의 무거운 상용 EDR 솔루션 없이 **OS 내장 로그(AUL)와 FSEvents의 조합만으로도 충분히 유의미한 탐지 정확도를 확보**했음을 시사합니다.

일부 탐지율의 한계(0.70)와 오탐(False Positive, 0.27)은 존재했으나, 이는 단일 이벤트 매칭이 아닌 **Threshold 및 Sequence 룰을 적용한 상관관계 분석**을 통해 실무 운영 단계에서 지속적으로 개선 가능한 수치입니다. 결론적으로 'macker'는 시스템 리소스를 최소화하면서도 핵심적인 위협을 효율적으로 선별해내는 경량화된 관제 도구로서의 가능성을 입증했습니다.

## **5. 마치며**

---

본 프로젝트는 macOS 환경에서 상대적으로 활용이 어려웠던 AUL을 실질적인 보안 탐지 데이터로 재해석하고, 단일 로그 소스의 한계를 FSEvents와의 결합으로 보완했다는 점에 의미가 있습니다. 

또한 “macOS 로그는 분석하기 어렵다”는 편견을 깨고, AUL과 보조 아티팩트의 조합만으로도 강력한 탐지 체계를 구축할 수 있음을 확인했습니다.

저희 팀은 이 연구 결과를 바탕으로**「macOS 버전별 AUL 차이점 분석」**논문을 발표하였으며, 실무자들을 위한 **「macOS 정보유출 분석 가이드라인」**과 자동화 스크립트도 함께 공개했습니다.

본 프로젝트가 macOS 보안에 관심 있는 분들께 저희의 경험이 도움이 되길 바랍니다!

### GitHub Link

[https://github.com/MACNEONTOP](https://github.com/MACNEONTOP)
