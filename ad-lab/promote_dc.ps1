# AD-DC01을 도메인 컨트롤러로 승격시킨다. DESIGN.md 31절.
# 호스트(Windows)에서 WinRM으로 AD-DC01에 직접 붙어서 실행한다(Kali 경유 아님 -
# 둘 다 같은 hostonly 네트워크에 있어서 호스트에서 바로 도달 가능).
#
# 사용법 (호스트 PowerShell에서):
#   $cred = New-Object PSCredential("Administrator", (ConvertTo-SecureString "Goad!Lab2026" -AsPlainText -Force))
#   Invoke-Command -ComputerName 192.168.56.XXX -Credential $cred -FilePath .\promote_dc.ps1

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

$safeModePwd = ConvertTo-SecureString "Goad!Lab2026" -AsPlainText -Force

Install-ADDSForest `
    -DomainName "goadlab.local" `
    -DomainNetbiosName "GOADLAB" `
    -SafeModeAdministratorPassword $safeModePwd `
    -InstallDns:$true `
    -Force:$true `
    -NoRebootOnCompletion:$false
