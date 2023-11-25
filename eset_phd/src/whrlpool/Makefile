all: whrlpool.lib

whrlpool.lib: wp_block.obj wp_dgst.obj
	LIB /OUT:$@ $**

clean:
	DEL *.lib *.obj
