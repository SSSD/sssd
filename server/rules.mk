etags:
	etags `find $(srcdir) -name "*.[ch]"`

ctags:
	ctags `find $(srcdir) -name "*.[ch]"`

.SUFFIXES: .c .o

.c.o:
	@echo Compiling $*.c
	@mkdir -p `dirname $@`
	@$(CC) $(CFLAGS) $(PICFLAG) -c $< -o $@

.c.po:
	@echo Compiling $*.c
	@mkdir -p `dirname $@`
	@$(CC) -fPIC $(CFLAGS) -c $< -o $@

showflags::
	@echo 'server will be compiled with flags:'
	@echo '  CFLAGS = $(CFLAGS)'
	@echo '  LIBS = $(LIBS)'

distclean::
	rm -f *~ */*~
