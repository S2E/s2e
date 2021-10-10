# Run this script in an admin powershell as follows:
# Set-ExecutionPolicy -Force -Scope Process Bypass; .\Setup-DevHost.ps1

# Install Chocolatey
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install some basic tools
choco install -y wget
choco install -y git
choco install -y rsync

# Install VS2019
choco install -y visualstudio2019community
choco install -y visualstudio2019-workload-nativedesktop  --package-parameters "--includeOptional --includeRecommended"

"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" modify --installPath "C:\Program Files (x86)\Microsoft Visual Studio\2019\community" --add Microsoft.VisualStudio.Component.VC.v141.x86.x64.Spectre --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre --add Microsoft.VisualStudio.Component.WinXP --quiet

choco install -y windows-sdk-8.1

# Download and install WDK 1903
cd $env:USERPROFILE
wget.exe -O wdk_setup.exe https://go.microsoft.com/fwlink/?linkid=2085767
& .\wdk_setup.exe /features + /l wdk.log /norestart /quiet | Out-Null

# The WDK installer does not install the VS extension in unattended mode. Do it manually.
& "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\vsixinstaller.exe" /q "C:\Program Files (x86)\Windows Kits\10\Vsix\VS2019\WDK.vsix" | Out-Null

# Install the OpenSSH Client and Server
dism /Online /Add-Capability /CapabilityName:OpenSSH.Client~~~~0.0.1.0
dism /Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0

# Set up SSH
sc.exe config sshd start= auto
sc.exe config ssh-agent start= auto

# Set up passwordless SSH
$SSHDir = "c:\Users\$env:USERNAME\.ssh"
$AuthorizedKeys = "$SSHDir\authorized_keys"

mkdir $SSHDir
New-Item -Path $AuthorizedKeys -ItemType File

# Repair-AuthorizedKeyPermission is supposed to fix passwordless login according to various
# tutorials, but in practice it breaks it.
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False
# Install-Module -Confirm:$False -Force OpenSSHUtils
# $ConfirmPreference = 'None'; Repair-AuthorizedKeyPermission $AuthorizedKeys -Confirm:$false

sc.exe start sshd
sc.exe start ssh-agent

# This will be used to convert PDBs into JSON files suitable for s2e-env
cd $env:USERPROFILE
wget.exe --no-check-certificate https://github.com/S2E/s2e/releases/download/v2.0.0/pdbparser.exe
