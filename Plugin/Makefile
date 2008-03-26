PROC=BinaryDiffer
IDA=C:\mat\DevEnv\idasdk50

IDA_LIBRARY_DIR="\mat\Projects\ResearchTools\Binary\Static Analysis\IDALib"

LOCAL_LIB_DIR=..\Lib
DIFF_ENGINE_DIR=..\DiffEngine
CPP=cl.exe

# -DINTERNAL_SERVER: For testing internal server
CPP_PROJ=/nologo /Gz /D "WIN32" /D "_CRT_SECURE_NO_DEPRECATE" /D "USE_DANGEROUS_FUNCTIONS" /D "_USE_IDA_SDK_49_OR_UPPER" /D "_USRDLL" /D "__NT__" /D "__IDP__" /D MAXSTR=1024 /Fo$(F) /c  /EHsc -D_MT /WX  -I"$(I)" -I..\AnalyzerConsole -I. /V0.1 -MTd /Zi -DEXTERNAL_SERVER="\"BinaryDiffer.exe\"" -I$(DIFF_ENGINE_DIR) -I$(LOCAL_LIB_DIR)

LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib user32.lib advapi32.lib version.lib "$(IDALIB)" $(LIBS) /nologo /dll /out:"$(BINARY)" /implib:$(F)$(PROC)$(A) /libpath:"$(L)" /export:PLUGIN /VERSION:0.1 /debug

I=$(IDA)\include\\
L=$(IDA)\libvc.w32\                   # libraries directory
R=bin\                         # results directory
F=.\vc.w32\                          # object files directory
SUBDIR=
PLUGIN=.plw                          # PLUGIN extension
O=.obj                               # object file extension
A=.lib                               # library file extension
RM=erase /q                          # File Remover
IDALIB=$(L)ida$(A)

OBJS=$(F)IDAAnalysis$(O) $(F)AnalysisServer$(O) $(F)fileinfo$(O) $(F)md5$(O) $(F)SharedMemory$(O) $(F)SharedSocket$(O) $(F)SocketOperation.obj $(F)ProcessUtils$(O) $(F)$(PROC)$(O)

BINARY=$(R)$(SUBDIR)$(PROC)$(PLUGIN)

all: $(R)$(SUBDIR) $(F) "$(BINARY)"

clean:
	-@$(RM) $(F)*$(O)
	-@$(RM) $(F)*$(A)
	-@$(RM) $(F)*.exp
	-@$(RM) "$(BINARY)"

distclean: clean
	-@$(RM) $(F)*
	rmdir $(F)

$(F):
	if not exist $(F) mkdir $(F)

$(R)$(SUBDIR):
	if not exist $(R)$(SUBDIR) mkdir $(R)$(SUBDIR)

.c{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

$(F)AnalysisServer.obj: $(LOCAL_LIB_DIR)\AnalysisServer.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\AnalysisServer.cpp

$(F)SharedMemory.obj: $(LOCAL_LIB_DIR)\SharedMemory.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\SharedMemory.cpp

$(F)SharedSocket.obj: $(LOCAL_LIB_DIR)\SharedSocket.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\SharedSocket.cpp
   
$(F)md5$(O): $(LOCAL_LIB_DIR)\md5.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\md5.cpp

$(F)fileinfo$(O): $(LOCAL_LIB_DIR)\fileinfo.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\fileinfo.cpp


$(F)IDAAnalysis$(O): $(LOCAL_LIB_DIR)\IDAAnalysis.cpp
		echo $(LOCAL_LIB_DIR)\IDAAnalysis.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\IDAAnalysis.cpp    

$(F)SocketOperation.obj: $(LOCAL_LIB_DIR)\SocketOperation.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\SocketOperation.cpp  

$(F)ProcessUtils.obj: $(LOCAL_LIB_DIR)\ProcessUtils.cpp
    $(CPP) $(CPP_PROJ) $(LOCAL_LIB_DIR)\ProcessUtils.cpp

.cpp{$(F)}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

.cpp{}.obj::
	$(CPP) @<<
  $(CPP_PROJ) $< 
<<

"$(BINARY)" : $(F) $(OBJS)
	$(LINK32) @<<
  $(LINK32_FLAGS) $(OBJS) 
<<
