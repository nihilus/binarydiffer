call "C:\Program Files\Microsoft Platform SDK\Setenv.cmd" /2000 /DEBUG
nmake
copy WIN2000_DEBUG\*.exe ..\bin
pause
