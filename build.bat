@echo off
rem Lefordítja a Karanten.exe-t a Windowsban meglévő .NET Framework fordítóval, külön SDK nélkül.
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
"%CSC%" /nologo /target:winexe /platform:anycpu /out:Karanten.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll src\Program.cs
if errorlevel 1 (echo Fordítási hiba. & exit /b 1)
echo Kész: Karanten.exe
