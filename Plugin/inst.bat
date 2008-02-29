call "C:\Program Files\Microsoft Platform SDK\Setenv.cmd" /2000 /DEBUG
nmake
copy bin\*.plw ..\bin\
pause
