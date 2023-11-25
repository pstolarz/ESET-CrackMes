MODDLL = FMJ8FR
LIBS = advapi32.lib user32.lib

all: eset_devel.exe $(MODDLL)

clean:
	DEL $(MODDLL) eset_devel.exe *.obj $(MODDLL).lib $(MODDLL).exp eset_devel.def stage5.h

eset_devel.def stage5.h: eset_devel.exe
	eset_devel.exe -30

$(MODDLL).obj: eset_devel.c stage5.h
	$(CC) $(CFLAGS) /c /DDLL_BUILD=1 /Fo$@ eset_devel.c

$(MODDLL): $(MODDLL).obj eset_devel.def
	LINK /DLL /DEF:eset_devel.def /OUT:$@ $(LIBS) $(MODDLL).obj

eset_devel.obj: eset_devel.c
	$(CC) $(CFLAGS) /c /Fo$@ eset_devel.c

eset_devel.exe: eset_devel.obj
	LINK /OUT:$@ $(LIBS) eset_devel.obj
