:: This scripts packages release binaries into the dist folder.
:: The resulting files may be uploaded to the github release page.

md dist
copy driver\s2e.inf dist
copy Release\s2e.sys dist\s2e32.sys
copy Release\s2e.pdb dist\s2e32.pdb
copy x64\Release\s2e.sys dist\s2e.sys
copy x64\Release\s2e.pdb dist\s2e.pdb
copy Release\drvctl.exe dist\drvctl32.exe
copy Release\pdbparser.exe dist\pdbparser32.exe
copy Release\libs2e32.dll dist
copy Release\tickler.exe dist\tickler32.exe
copy x64\Release\drvctl.exe dist\drvctl.exe
copy x64\Release\pdbparser.exe dist\pdbparser.exe
copy x64\Release\libs2e64.dll dist
copy x64\Release\tickler.exe dist\tickler64.exe


dist\pdbparser.exe -l dist\s2e.sys dist\s2e.pdb > dist\s2e.sys.lines
dist\pdbparser.exe -l dist\s2e32.sys dist\s2e32.pdb > dist\s2e32.sys.lines

:: Uncomment this to copy binaries to the guesttools folders on the host
goto end
copy dist\drvctl.exe "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools64\drvctl.exe"
copy dist\drvctl32.exe "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools32\drvctl.exe"

copy dist\libs2e64.dll "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools64"
copy dist\libs2e32.dll "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools64"
copy dist\libs2e32.dll "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools32"

copy dist\tickler64.exe "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools64\tickler.exe"
copy dist\tickler32.exe "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools32\tickler.exe"

copy dist\s2e.sys "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools64"
copy dist\s2e32.sys "\\vmware-host\Shared Folders\s2e\env\install\bin\guest-tools32\s2e.sys"
:end
