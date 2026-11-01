@echo off
setlocal
set "CSC=C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\Roslyn\csc.exe"
set "REF=C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2"
set "HERE=%~dp0"
pushd "%HERE%"
"%CSC%" /nologo /noconfig /nostdlib+ /target:winexe /platform:x64 /optimize+ /warn:4 /codepage:65001 /utf8output ^
  /win32manifest:app.manifest ^
  /out:..\RegistroScanner.exe ^
  /r:"%REF%\mscorlib.dll" /r:"%REF%\System.dll" /r:"%REF%\System.Core.dll" ^
  /r:"%REF%\System.Windows.Forms.dll" /r:"%REF%\System.Drawing.dll" /r:"%REF%\Microsoft.CSharp.dll" ^
  src\*.cs
set "RC=%ERRORLEVEL%"
popd
if not "%RC%"=="0" (echo BUILD FALLITA ^(%RC%^)) else (echo BUILD OK)
exit /b %RC%
