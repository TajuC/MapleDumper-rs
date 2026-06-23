; Per-user component installer for the MapleDumper native dumper (maple-unpack-native + unicorn.dll).
; Installs into the directory the CLI and desktop app search (%LOCALAPPDATA%\MapleDumper\bin), so once
; this runs, both surfaces find the native unpacker with no configuration and no admin rights. The
; native dumper drives the protected client, so installing it is a deliberate opt-in to that feature.

Unicode true

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef SRCDIR
  !define SRCDIR "."
!endif
!define REGKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\MapleDumperNativeUnpacker"

Name "MapleDumper Native Unpacker ${VERSION}"
OutFile "MapleDumper_NativeUnpacker_${VERSION}_x64-setup.exe"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\MapleDumper\bin"
ShowInstDetails show
ShowUninstDetails show

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Native dumper" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"
  File "${SRCDIR}\maple-unpack-native.exe"
  File "${SRCDIR}\unicorn.dll"
  WriteUninstaller "$INSTDIR\uninstall-native-unpacker.exe"
  WriteRegStr HKCU "${REGKEY}" "DisplayName" "MapleDumper Native Unpacker"
  WriteRegStr HKCU "${REGKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${REGKEY}" "Publisher" "TajuC"
  WriteRegStr HKCU "${REGKEY}" "UninstallString" "$\"$INSTDIR\uninstall-native-unpacker.exe$\""
  WriteRegStr HKCU "${REGKEY}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKCU "${REGKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${REGKEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\maple-unpack-native.exe"
  Delete "$INSTDIR\unicorn.dll"
  Delete "$INSTDIR\uninstall-native-unpacker.exe"
  DeleteRegKey HKCU "${REGKEY}"
  RMDir "$INSTDIR"
SectionEnd
