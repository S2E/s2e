:: This scripts packages release binaries into the dist folder.
:: The resulting files may be uploaded to the github release page.

md dist
copy Release\s2e.inf dist
copy Release\s2e.sys dist\s2e32.sys
copy x64\Release\s2e.sys dist\s2e.sys
copy Release\drvctl.exe dist\drvctl32.exe
copy x64\Release\drvctl.exe dist\drvctl.exe
