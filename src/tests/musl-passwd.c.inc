/*
The code in this file is taked from the passwd/ subdir of the musl project.
musl as a whole is licensed under the following standard MIT license:

----------------------------------------------------------------------
Copyright © 2005-2020 Rich Felker, et al.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
----------------------------------------------------------------------
*/

static static unsigned atou(char **s)
{
	unsigned x;
	for (x=0; **s-'0'<10U; ++*s) x=10*x+(**s-'0');
	return x;
}

static int __getpwent_a(FILE *f, struct passwd *pw, char **line, size_t *size, struct passwd **res)
{
	ssize_t l;
	char *s;
	int rv = 0;
	//int cs;
	//pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	for (;;) {
		if ((l=getline(line, size, f)) < 0) {
			rv = ferror(f) ? errno : 0;
			free(*line);
			*line = 0;
			pw = 0;
			break;
		}
		line[0][l-1] = 0;

		s = line[0];
		pw->pw_name = s++;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_passwd = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_uid = atou(&s);
		if (*s != ':') continue;

		*s++ = 0; pw->pw_gid = atou(&s);
		if (*s != ':') continue;

		*s++ = 0; pw->pw_gecos = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_dir = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; pw->pw_shell = s;
		break;
	}
	//pthread_setcancelstate(cs, 0);
	*res = pw;
	if (rv) errno = rv;
	return rv;
}

static int __getgrent_a(FILE *f, struct group *gr, char **line, size_t *size, char ***mem, size_t *nmem, struct group **res)
{
	ssize_t l;
	char *s, *mems;
	size_t i;
	int rv = 0;
	//int cs;
	//pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	for (;;) {
		if ((l=getline(line, size, f)) < 0) {
			rv = ferror(f) ? errno : 0;
			free(*line);
			*line = 0;
			gr = 0;
			goto end;
		}
		line[0][l-1] = 0;

		s = line[0];
		gr->gr_name = s++;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; gr->gr_passwd = s;
		if (!(s = strchr(s, ':'))) continue;

		*s++ = 0; gr->gr_gid = atou(&s);
		if (*s != ':') continue;

		*s++ = 0; mems = s;
		break;
	}

	for (*nmem=!!*s; *s; s++)
		if (*s==',') ++*nmem;
	free(*mem);
	*mem = calloc(sizeof(char *), *nmem+1);
	if (!*mem) {
		rv = errno;
		free(*line);
		*line = 0;
		gr = 0;
		goto end;
	}
	if (*mems) {
		mem[0][0] = mems;
		for (s=mems, i=0; *s; s++)
			if (*s==',') *s++ = 0, mem[0][++i] = s;
		mem[0][++i] = 0;
	} else {
		mem[0][0] = 0;
	}
	gr->gr_mem = *mem;
end:
	//pthread_setcancelstate(cs, 0);
	*res = gr;
	if(rv) errno = rv;
	return rv;
}

static struct passwd *fgetpwent(FILE *f)
{
	static char *line;
	static struct passwd pw;
	size_t size=0;
	struct passwd *res;
	__getpwent_a(f, &pw, &line, &size, &res);
	return res;
}

static struct group *fgetgrent(FILE *f)
{
	static char *line, **mem;
	static struct group gr;
	struct group *res;
	size_t size=0, nmem=0;
	__getgrent_a(f, &gr, &line, &size, &mem, &nmem, &res);
	return res;
}
