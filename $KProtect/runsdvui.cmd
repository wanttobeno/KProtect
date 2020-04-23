cd /d "D:\搜狗高速下载\$KProtect\$KProtect" &msbuild "$KProtect.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform=Win32
exit %errorlevel% 