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
copy x64\Release\drvctl.exe dist\drvctl.exe
copy x64\Release\pdbparser.exe dist\pdbparser.exe


dist\pdbparser.exe -l dist\s2e.sys dist\s2e.pdb > dist\s2e.sys.lines
dist\pdbparser.exe -l dist\s2e32.sys dist\s2e32.pdb > dist\s2e32.sys.lines
