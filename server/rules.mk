etags:
	etags `find $(srcdir) -name "*.[ch]"`

ctags:
	ctags `find $(srcdir) -name "*.[ch]"`

.SUFFIXES: .c .o .xml .1.xml .3.xml .5.xml .8.xml .1 .3 .5 .8

.c.o:
	@echo Compiling $*.c
	@mkdir -p `dirname $@`
	@$(CC) $(CFLAGS) $(PICFLAG) -c $< -o $@

.c.po:
	@echo Compiling $*.c
	@mkdir -p `dirname $@`
	@$(CC) -fPIC $(CFLAGS) -c $< -o $@

.1.xml.1:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

.3.xml.3:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

.5.xml.5:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

.8.xml.8:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

showflags::
	@echo 'server will be compiled with flags:'
	@echo '  CFLAGS = $(CFLAGS)'
	@echo '  LIBS = $(LIBS)'

distclean::
	rm -f *~ */*~
