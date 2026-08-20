# Pentest Report: 20260809-233332-msf2-e2e
## Summary

- 대상: 192.168.56.105
- 진행된 단계: exploitation, scanning, vuln_analysis
- 총 findings: 35


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
| 3306 | mysql | MySQL 5.0.51a-3ubuntu5 |
| 5432 | postgresql | PostgreSQL DB 8.3.0 - 8.3.7 |
| 8180 | http | Apache Tomcat/Coyote JSP engine 1.1 |
- `ftp_enum` 결과: {'anonymous_login_ok': True, 'listing': ''}
- `http_enum` 결과: {'whatweb': 'http://192.168.56.105:80 [200 OK] Apache[2.2.8], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.2.8 (Ubuntu) DAV/2], IP[192.168.56.105], PHP[5.2.4-2ubuntu5.10], Title[Metasploitable2 - Linux], WebDAV[2], X-Powered-By[PHP/5.2.4-2ubuntu5.10]', 'gobuster': '.hta                 (...
- `http_enum` 결과: {'whatweb': 'http://192.168.56.105:8180 [200 OK] Apache, Country[RESERVED][ZZ], Email[dev@tomcat.apache.org,users@tomcat.apache.org], HTTPServer[Apache-Coyote/1.1], IP[192.168.56.105], PoweredBy[Tomcat], Title[Apache Tomcat/5.5]', 'gobuster': 'admin                (Status: 302) [Size: 0] [--> http:/...
- `smb_enum` 결과: {'enum4linux': ''}


## Vulnerability Analysis

### 192.168.56.105

- **port 21 (ftp)** - confidence 0.95, risk `medium` - vsftpd 2.3.4는 소스에 백도어가 삽입된 것으로 알려진 특정 버전이며, 배너가 정확히 일치하므로 CVE-2011-2523 백도어 취약점이 실제로 존재할 가능성이 매우 높다. 익스플로잇은 활성화 시 셸을 획득하는 방식으로 서비스 크래시보다는 백도어 리스너(6200/tcp) 생성이 주된 결과지만, 실패 시 FTP 데몬이 비정상 상태로 남거나 재시작이 필요할 수 있어 중간 정도의 위험이 존재한다.
- **port 80 (http)** - confidence 0.40, risk `high` - Apache 2.2.8은 CVE-2011-3192(Range 헤더 DoS)에 취약한 버전대에 해당하며 DAV/2 모듈도 과거 여러 취약점 이력이 있으나, searchsploit에 직접 매칭되는 익스플로잇이 없어 신뢰도는 중간 정도이다. 해당 취약점들은 대부분 서비스 다운(DoS)을 유발하는 특성이 있어 시도 시 서비스가 죽을 위험이 높다.
- **port 53 (domain)** - confidence 0.30, risk `medium` - ISC BIND 9.4.2는 매우 오래된 버전으로 CVE-2008-0122, CVE-2009-0025 등 DoS 취약점이 존재하지만 searchsploit 후보가 비어있어 검증된 공개 익스플로잇이 부재하다. 캐시 포이즈닝이나 DoS 시도는 서비스 크래시나 존 재기동을 유발할 가능성이 있어 신중한 접근이 필요하다.
- **port 23 (telnet)** - confidence 0.25, risk `high` - 배너에 버전 정보가 없어 GNU InetUtils, netkit-telnet, 특정 encrypt_keyid 취약 버전과의 일치 여부를 확인할 수 없다. 세 후보 모두 특정 버전/빌드에 의존적이며, 특히 18280(함수 포인터 오버라이트)과 48170(RCE)은 실패 시 telnetd 프로세스를 크래시시킬 가능성이 높다.
- **port 22 (ssh)** - confidence 0.20, risk `low` - OpenSSH 4.7p1은 오래된 버전이나 searchsploit에서 매칭되는 익스플로잇이 없고, 알려진 취약점(CVE-2008-0166 등)은 대부분 로컬 권한상승이나 특정 Debian OpenSSL 키 생성 결함과 관련되어 원격 서비스 크래시와는 무관하다. 실제 원격 코드실행이나 크래시를 유발할 공개 익스플로잇이 확인되지 않아 시도 가치와 위험도 모두 낮다.
- **port 3306 (mysql)** - confidence 0.20, risk `low` - MySQL 5.0.51a는 오래된 버전이지만 searchsploit에서 매칭되는 익스플로잇이 없고, CVE-2012-2122 같은 인증 우회는 5.1 이상 버전에 주로 해당되어 이 버전에는 적용되지 않는다. 실제로 시도할 만한 신뢰도 높은 취약점이 없어 성공 가능성은 낮다.
- **port 8180 (http)** - confidence 0.20, risk `low` - 배너에 구체적인 Tomcat 버전 정보가 없어 특정 CVE를 매칭하기 어렵고 searchsploit 결과도 없다. Coyote/1.1은 매우 광범위한 버전대에서 나타나는 일반적인 배너로 신뢰할 만한 익스플로잇 후보를 특정할 수 없다. 무작위 익스플로잇 시도는 서비스 크래시보다는 실패로 끝날 가능성이 높아 위험도는 낮다.
- **port 139 (netbios-ssn)** - confidence 0.20, risk `medium` - 배너가 Samba 3.X-4.X로 범위가 너무 넓어 특정 CVE(예: CVE-2017-7494)에 해당하는지 특정할 수 없고, searchsploit 결과도 없어 확실한 익스플로잇 후보가 아니다. 다만 알려진 Samba RCE/DoS 취약점들은 익스플로잇 시도 시 smbd 프로세스 크래시나 서비스 중단을 유발할 가능성이 있어 위험도는 중간으로 판단된다.
- **port 5432 (postgresql)** - confidence 0.20, risk `medium` - PostgreSQL 8.3.0-8.3.7은 오래된 버전으로 알려진 CVE(예: CVE-2008-3826, CVE-2009-3231 등)가 존재하지만 searchsploit 후보가 비어있어 즉시 사용 가능한 공개 익스플로잇이 확인되지 않는다. 인증 우회나 권한상승 취약점이 이론적으로 존재하나 대부분 인증된 접근이나 특정 설정을 요구해 원격 무인증 공격 성공률은 낮다. 취약점 시도 시 서비스 크래시보다는 실패 가능성이 높아 위험도는 중간 정도로 평가한다.
- **port 445 (netbios-ssn)** - confidence 0.15, risk `medium` - 배너가 Samba 3.X-4.X로 매우 광범위하여 특정 CVE(예: CVE-2017-7494)를 특정할 근거가 부족하고 searchsploit 매칭 결과도 없다. 정확한 마이너 버전 없이는 신뢰도 있는 익스플로잇 선택이 어렵고, 잘못된 익스플로잇 시도 시 smbd 프로세스 크래시 가능성이 있어 위험도는 중간으로 평가된다.
- **port 111 (rpcbind)** - confidence 0.10, risk `medium` - rpcbind 자체는 알려진 원격 코드실행 취약점이 거의 없고 searchsploit 결과도 없어 직접적인 익스플로잇 후보는 미약하다. 다만 정보 노출(rpcinfo를 통한 서비스 열거)이나 NFS/NIS 등 연계된 RPC 서비스 공격의 진입점으로 활용될 위험은 있다. 서비스 자체를 다운시키는 크래시형 익스플로잇은 드물어 안정성 위험은 중간 정도로 평가된다.
- **port 25 (smtp)** - confidence 0.05, risk `low` - Postfix smtpd는 배너만으로 특정 취약점을 특정할 수 없고 searchsploit 결과도 없어 알려진 익스플로잇이 없다. Postfix는 보안 이력이 매우 양호한 소프트웨어로 실제 통할 만한 취약점 후보로 보기 어렵다. 서비스 크래시 위험도 낮지만, 무작위 시도 자체의 실효성이 낮다.


## Exploitation

### 192.168.56.105

- **[실패]** port 21 - vsftpd 2.3.4 - Backdoor Command Execution (Metasploit) (방법: PoC 복사 실패: timed out after 20s (guest session force-closed))

