# Pentest Report: 20260810-143041-full-pipeline-verify
## Summary

- 대상: 192.168.56.105
- 진행된 단계: exploitation, scanning, vuln_analysis
- 총 findings: 88


## Scanning

### 192.168.56.105
- 플랫폼 추정: `windows_standalone`

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
| 513 | login |  |
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
| 42935 | mountd | 1-3 (RPC #100005) |
| 44956 | java-rmi | GNU Classpath grmiregistry |
| 57453 | status | 1 (RPC #100024) |
| 57830 | nlockmgr | 1-4 (RPC #100021) |
- `ftp_enum` 결과: {'anonymous_login_ok': True, 'listing': ''}
- `http_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `smb_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `ftp_enum` 결과: {'error': 'Kali 세션 락을 90s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck'}
- `http_enum` 결과: {'whatweb': 'http://192.168.56.105:8180 [200 OK] Apache, Country[RESERVED][ZZ], Email[dev@tomcat.apache.org,users@tomcat.apache.org], HTTPServer[Apache-Coyote/1.1], IP[192.168.56.105], PoweredBy[Tomcat], Title[Apache Tomcat/5.5]', 'gobuster': ''}


## Vulnerability Analysis

### 192.168.56.105

- **port 1524 (bindshell)** - confidence 0.95, risk `low` - Metasploitable의 포트 1524는 잘 알려진 백도어 루트 쉘로, 이전 침해(예: distcc 또는 ingreslock 취약점 악용)로 인해 열려 있는 인증 없는 root 쉘입니다. 단순히 접속만 하면 즉시 root 권한을 얻을 수 있어 별도의 익스플로잇 코드 없이도 통하며, 서비스 자체가 불안정한 서비스 데몬이 아니라 단순 리스너이므로 크래시 위험은 거의 없습니다. searchsploit 후보가 없는 것은 이것이 CVE 기반 취약점이 아니라 설정/침해 상태이기 때문입니다.
- **port 3632 (distccd)** - confidence 0.85, risk `medium` - distccd는 CVE-2004-2687로 알려진 원격 명령 실행 취약점이 존재하며, 인증 없이 컴파일 요청을 받아 실행하는 구조적 결함으로 임의 명령 실행이 가능하다. searchsploit에는 안 나오지만 Metasploit의 distcc_exec 모듈로 잘 알려진 공격이라 성공 가능성이 높다. 서비스 자체가 명령 실행을 위해 설계되어 있어 크래시보다는 성공적인 코드 실행 위험이 크므로 risk는 medium으로 판단한다.
- **port 8787 (drb)** - confidence 0.85, risk `high` - Ruby DRb는 인증 없이 원격 객체 메서드 호출을 허용하며, 특히 Ruby 1.8 환경에서는 send 메서드 등을 통한 임의 코드 실행(RCE)이 공개적으로 알려진 취약점(예: metasploit의 druby_remote_codeexec)이다. searchsploit에 항목이 없어도 DRb 자체의 설계 결함으로 실제 공격이 통할 가능성이 높다. 다만 익스플로잇 시도 시 서비스 프로세스가 크래시되거나 예기치 않게 종료될 위험이 크므로 risk는 high로 판단된다.
- **port 2121 (ftp)** - confidence 0.30, risk `medium` - ProFTPD 1.3.1은 이후 버전들과 달리 유명한 mod_copy나 backdoor 취약점의 직접 대상은 아니며, searchsploit에서도 매칭되는 익스플로잇이 없어 확실한 공개 취약점 근거가 부족하다. 다만 오래된 버전이라 잠재적 버그(예: 명령 처리 관련 결함)가 있을 수 있어 완전히 안전하다고 보기도 어렵다.
- **port 8009 (ajp13)** - confidence 0.30, risk `medium` - AJP13은 Tomcat 등에서 Ghostcat(CVE-2020-1938)과 같은 파일 읽기/포함 취약점의 배경이 될 수 있으나, 배너만으로는 실제 서버 종류나 버전을 특정할 수 없어 매칭 신뢰도가 낮다. AJP는 바이너리 프로토콜이라 malformed 패킷 전송 시 파싱 오류로 서비스가 비정상 종료될 위험이 있어 risk는 medium으로 판단된다.
- **port 44956 (java-rmi)** - confidence 0.30, risk `medium` - Java RMI 레지스트리는 역직렬화 기반 원격 코드 실행(예: ysoserial 계열 가젯체인)에 취약할 수 있으나, GNU Classpath grmiregistry는 표준 Oracle JDK RMI 구현과 코드베이스가 달라 알려진 CVE/공개 익스플로잇이 매칭되지 않을 가능성이 높다. searchsploit 결과가 없다는 점도 이를 뒷받침하며, 시도 시 서비스 크래시나 예기치 않은 동작 가능성이 있어 위험도는 중간으로 판단된다.
- **port 23 (telnet)** - confidence 0.25, risk `high` - 배너에 구체적인 telnetd 구현체나 버전 정보가 없어 후보 중 어떤 것이 실제로 해당하는지 특정할 수 없다. encrypt_keyid나 BraveStarr류는 메모리 손상 기반 익스플로잇이라 버전 불일치 시 서비스 크래시나 불안정화 위험이 크다.
- **port 80 (http)** - confidence 0.20, risk `low` - Apache 2.2.8과 mod_dav는 매우 오래된 버전이지만 searchsploit에서 직접적인 익스플로잇 후보가 나오지 않았다. 알려진 취약점(예: 정보노출, 일부 DoS)은 있으나 원격 코드실행급은 아니며 실제 성공 가능성은 낮다. 서비스 크래시 위험도 낮은 편이다.
- **port 3306 (mysql)** - confidence 0.20, risk `low` - MySQL 5.0.51a는 오래된 버전이지만 searchsploit에서 직접적인 익스플로잇이 검색되지 않았고, CVE-2012-2122 같은 유명한 인증 우회는 주로 5.1/5.5 이후 버전에 해당되어 이 버전에는 신뢰성 있게 적용되지 않는다. 실제 원격 크래시나 RCE로 이어질 확률은 낮다.
- **port 8180 (http)** - confidence 0.20, risk `low` - 배너 정보만으로는 정확한 Tomcat 버전을 특정할 수 없고 Coyote/1.1 표기는 오래되고 일반적인 문자열이라 특정 CVE와 매칭하기 어려움. searchsploit 후보도 없어 알려진 익스플로잇을 바로 적용하기 어려우며, 무작위 시도는 서비스 안정성에 큰 영향을 주지 않을 가능성이 높음.
- **port 53 (domain)** - confidence 0.20, risk `medium` - ISC BIND 9.4.2는 매우 오래된 버전으로 CVE-2008-0122, CVE-2009-0025 등 DoS 취약점이 알려져 있으나 searchsploit에서 매칭되는 공개 익스플로잇이 없어 즉시 사용 가능한 코드가 부족하다. 배너 정보만으로 정확한 패치 레벨을 알 수 없어 실제 공격 성공 여부는 불확실하며, DNS 서비스 특성상 잘못된 패킷 전송 시 캐시 손상이나 서비스 크래시 위험이 존재한다.
- **port 22 (ssh)** - confidence 0.20, risk `medium` - OpenSSH 4.7p1은 매우 오래된 버전으로 CVE-2008-5161(CBC 모드 정보 노출), 구버전 X11/포워딩 관련 이슈 등이 이론상 존재하지만 대부분 정보 노출성이고 원격 코드 실행급 익스플로잇은 공개된 것이 거의 없다. searchsploit 결과가 비어있어 즉시 사용할 수 있는 실전 익스플로잇이 없으며, 브루트포스나 설정 취약점 외에는 신뢰도가 낮다. 서비스 크래시 위험은 낮으나 실효성 있는 공격 성공률도 낮다.
- **port 139 (netbios-ssn)** - confidence 0.20, risk `medium` - 배너가 Samba 3.X-4.X라는 광범위한 버전대만 나타내어 특정 CVE(예: CVE-2017-7494 등)를 특정할 수 없고, searchsploit 결과도 없어 즉시 통할 익스플로잇이 확인되지 않는다. 정확한 마이너 버전 없이 공격을 시도하면 실패 확률이 높고, 일부 취약점(예: 원격 코드 실행류)은 성공 시 서비스 크래시나 비정상 종료를 유발할 가능성이 있어 위험도는 중간으로 판단된다.
- **port 445 (netbios-ssn)** - confidence 0.20, risk `medium` - 배너가 Samba 3.X-4.X라는 광범위한 버전대만 나타내며 정확한 마이너 버전을 알 수 없어 특정 CVE(예: CVE-2017-7494 등) 적용 가능성을 단정하기 어렵다. searchsploit 후보가 없어 즉시 활용 가능한 공개 익스플로잇이 확인되지 않았으므로 신뢰도는 낮다. 다만 SMB 서비스 특성상 잘못된 익스플로잇 시도 시 서비스 크래시나 데몬 중단 가능성이 있어 위험도는 중간으로 판단된다.
- **port 1099 (java-rmi)** - confidence 0.20, risk `medium` - Java RMI 레지스트리는 역직렬화 기반 원격 코드 실행에 취약한 사례가 많지만, GNU Classpath의 grmiregistry는 표준 Oracle JDK RMI와 구현이 달라 알려진 공개 익스플로잇(searchsploit 결과 없음)이 없어 즉시 통할 가능성은 낮다. 다만 RMI 프로토콜 자체를 다루는 공격(예: JMX, 임의 클래스 로딩 유도)을 시도하면 서비스가 예외로 크래시되거나 불안정해질 위험이 존재한다.
- **port 5900 (vnc)** - confidence 0.20, risk `medium` - VNC 3.3 프로토콜은 인증 우회나 취약한 DES 키 처리 등 알려진 이슈가 있었으나 searchsploit 결과가 없어 구체적 CVE/익스플로잇 매칭이 불확실하다. 대부분 취약점은 인증 없는 접근이나 약한 암호화에 의존하며 서버 크래시보다는 정보노출/무단접근 쪽 위험이 크다. 실제 구현체(RealVNC, TightVNC 등)에 따라 결과가 달라 신뢰도는 낮게 설정한다.
- **port 5432 (postgresql)** - confidence 0.20, risk `medium` - PostgreSQL 8.3.x는 EOL 버전으로 CVE-2013-1899(잘못된 접속 문자열 처리), CVE-2012-0866(contrib pgcrypto) 등 알려진 결함이 있으나 searchsploit 후보가 없어 즉시 사용 가능한 완성된 익스플로잇은 부재하다. 인증 없이 원격 코드 실행이나 서비스 크래시를 유발하는 신뢰도 높은 공개 PoC은 흔치 않아 확신도가 낮고, 인증 관련 취약점 시도 시 연결 실패나 프로세스 재시작 정도의 중간 수준 위험이 있다.
- **port 111 (rpcbind)** - confidence 0.10, risk `low` - rpcbind 자체는 포트 매핑 서비스로 알려진 RCE 취약점이 거의 없으며, searchsploit에서도 매칭되는 익스플로잇이 없다. 주로 정보 노출(rpcinfo 열거)이나 UDP 기반 증폭 공격에 활용되는 수준이라 서비스 크래시 위험은 낮지만 실질적 공격 성공 가능성도 낮다.
- **port 512 (exec)** - confidence 0.10, risk `low` - netkit-rsh rexecd는 알려진 원격 코드실행 취약점이 공개되어 있지 않고 searchsploit 결과도 없음. 인증 없이 명령을 실행할 수 있는 설계 자체가 취약점이지만 이는 서비스 오작동이 아닌 정상 기능이므로 서비스 크래시 위험은 낮음. 다만 평문 인증정보 전송 및 접근제어 부재로 인한 악용 가능성은 존재.
- **port 2049 (nfs)** - confidence 0.10, risk `medium` - NFS(RPC #100003) 배너 정보만으로는 특정 버전이나 알려진 CVE를 식별할 수 없고, searchsploit 결과도 없어 공개된 익스플로잇이 확인되지 않는다. NFS는 설정(exports, 인증 방식)에 따라 취약점 양상이 크게 달라지므로 버전 정보만으로 신뢰도 높은 공격을 판단하기 어렵다. 무작정 시도할 경우 마운트 오류나 서비스 응답 불능을 유발할 수 있어 중간 정도의 위험으로 평가한다.
- **port 514 (shell)** - confidence 0.10, risk `medium` - Netkit rshd(rsh 데몬)는 인증 메커니즘 자체가 IP/포트 기반의 취약한 신뢰 관계(.rhosts)에 의존하는 근본적으로 취약한 프로토콜이지만, 이는 설계상의 인증 우회 문제이며 특정 CVE로 등록된 메모리 손상성 익스플로잇이 존재하지 않아 searchsploit 결과가 없는 것과 일치한다. 실제 공격은 소스 포트 스푸핑이나 신뢰 관계 악용 형태로 이루어지며 서비스 크래시를 유발할 원격 코드 실행형 익스플로잇은 알려진 바 없어 위험도는 중간, 성공 확률은 낮게 판단된다.
- **port 6000 (X11)** - confidence 0.10, risk `medium` - 배너가 'access denied'로 X11 접근 제어(MIT-MAGIC-COOKIE 등)가 활성화되어 있어 인증 없이 접근이 차단된 상태로 보인다. searchsploit 결과도 없어 즉시 적용 가능한 공개 익스플로잇이 없으며, 인증 우회 없이는 실질적 공격 표면이 제한적이다. 무리하게 프로토콜 레벨 요청을 반복 시도할 경우 서비스 불안정 가능성이 있어 위험도는 중간으로 판단한다.
- **port 42935 (mountd)** - confidence 0.10, risk `medium` - mountd(RPC #100005)는 NFS 마운트 요청을 처리하는 서비스로, searchsploit에서 매칭되는 공개 익스플로잇이 없어 즉시 활용 가능한 취약점이 확인되지 않는다. 버전 정보(1-3)만으로는 특정 CVE를 특정하기 어렵고, 오래된 NFS 구현에서 알려진 취약점들은 대상 환경에 존재하지 않을 가능성이 높다. 임의의 RPC 조작 시도는 서비스 크래시나 마운트 데몬 응답 불능을 유발할 수 있어 중간 정도의 위험이 있다.
- **port 57453 (status)** - confidence 0.10, risk `medium` - status(rpc.statd, RPC #100024)는 포트맵 등록 서비스로 과거 CVE-2003-0028 등 스택 오버플로 취약점 이력이 있으나 searchsploit 후보가 없어 특정 버전 매칭 익스플로잇 확인 불가. 배너 정보만으로는 취약 여부 판단이 어렵고, 시도 시 서비스 크래시 가능성이 있어 주의가 필요하다.
- **port 57830 (nlockmgr)** - confidence 0.10, risk `medium` - nlockmgr(NLM, RPC #100021)는 NFS 파일 잠금 관리 데몬으로 과거 DoS 취약점 사례가 있으나 searchsploit에 매칭되는 공개 익스플로잇이 없어 즉시 활용 가능한 취약점 확증이 어렵다. RPC 서비스 특성상 잘못된 요청이나 퍼징 시 데몬 crash 또는 NFS 잠금 상태 불안정을 유발할 가능성이 있어 위험도는 중간으로 판단된다. 버전 정보만으로는 특정 CVE에 매칭하기 부족해 confidence는 낮게 책정한다.
- **port 25 (smtp)** - confidence 0.05, risk `low` - 배너에는 버전 정보가 없고 Postfix smtpd 자체는 보안 이력이 매우 양호하여 알려진 원격 코드실행 취약점이 거의 없다. searchsploit 결과도 없어 특정 CVE를 겨냥한 공격은 근거가 부족하며, 일반적인 SMTP 명령 퍼징이나 오래된 취약점 시도는 서비스 중단 가능성보다는 실패할 가능성이 높다. 설정 오류(오픈 릴레이 등) 점검은 가능하나 이는 익스플로잇이라기보다 정찰 수준이다.
- **port 513 (login)** - confidence 0.03, risk `low` - 포트 513은 rlogin(BSD 원격 로그인) 프로토콜이며 검색된 익스플로잇 후보들은 모두 웹 애플리케이션의 login.php/asp 관련 SQL 인젝션·XSS 취약점으로 전혀 다른 서비스 유형이다. rlogin 자체 배너 정보 없이 이 웹앱 취약점들을 적용할 근거가 없어 실제로 통할 가능성은 매우 낮다. 다만 이 익스플로잇들을 그대로 시도해도 rlogin 데몬에 직접적인 충돌을 일으킬 프로토콜적 연결점이 없어 서비스 다운 위험 자체는 낮다.


## Exploitation

### 192.168.56.105

- **[실패]** port 23 - GNU InetUtils 2.6 - Telnetd Remote Privilege Escalation (방법: Metasploit(exploit/linux/telnet/gnu_inetutils_auth_bypass))
  - Exploit completed but no session was created, and the active sessions list shows no active sessions, indicating the exploit failed to achieve code execution.
- **[실패]** port 23 - netkit-telnet-0.17 telnetd (Fedora 31) - 'BraveStarr' Remote Code Execution (방법: PoC 스크립트)
  - 스크립트가 필수 method 인자(leak/command/shell)를 누락하여 argparse 사용법 오류만 출력했고, 대상에 대한 실제 명령 실행이나 세션 획득은 이루어지지 않았다.
- **[실패]** port 23 - TelnetD encrypt_keyid - Function Pointer Overwrite (방법: Metasploit(exploit/freebsd/telnet/telnet_encrypt_keyid))
  - 타겟 시스템이 암호화를 지원하지 않아 익스플로잯이 중단되었고(Exploit aborted due to failure), 세션 목록에도 활성 세션이 없음(No active sessions).
- **[실패]** port 513 - Airties - login-cgi Buffer Overflow (Metasploit) (방법: Metasploit(exploit/linux/http/airties_login_cgi_bof))
  - Exploit failed with Errno::ECONNRESET and no session was created; active sessions list is empty, indicating the exploit did not achieve code execution.

