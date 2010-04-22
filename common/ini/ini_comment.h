/*
    INI LIBRARY

    Header file for comment object.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2010

    INI Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    INI Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with INI Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef INI_COMMENT_H
#define INI_COMMENT_H

#include <stdint.h>
#include <stdio.h>

#ifndef EOK
#define EOK 0
#endif

struct ini_comment;

/**
 * Create a comment object
 */
int ini_comment_create(struct ini_comment **ic);

/**
 * Destroy the comment object
 */
void ini_comment_destroy(struct ini_comment *ic);

/**
 * Build up a comment object - use this when reading
 * comments from a file.
 */
int ini_comment_build(struct ini_comment *ic,
                      const char *line);

/**
 * Modify comment by instering a line.
 *
 * idx can be:
 * 0 - as first
 * 1 - after first
 * 2 - after second
 * ...
 * If greater than number of lines
 * missing lines are added automatically
 * as empty lines
 */
int ini_comment_insert(struct ini_comment *ic,
                       uint32_t idx,
                       const char *line);

/* Modify comment by appending a line. */
int ini_comment_append(struct ini_comment *ic,
                       const char *line);

/* Remove line from the comment.*/
int ini_comment_remove(struct ini_comment *ic,
                       uint32_t idx);

/* Clear line in the comment. Line is replaced with an empty line */
int ini_comment_clear(struct ini_comment *ic,
                      uint32_t idx);

/* Replace a line in the comment */
int ini_comment_replace(struct ini_comment *ic,
                        uint32_t idx,
                        const char *line);

/* Reset the comment - clean all lines.*/
int ini_comment_reset(struct ini_comment *ic);

/* Get number of lines */
int ini_comment_get_numlines(struct ini_comment *ic,
                             uint32_t *num);

/* Get line */
int ini_comment_get_line(struct ini_comment *ic,
                         uint32_t idx,
                         char **line);

/* Swap lines */
int ini_comment_swap(struct ini_comment *ic,
                     uint32_t idx1,
                     uint32_t idx2);


/* Internal function to print comment */
void ini_comment_print(struct ini_comment *ic, FILE *file);


#endif
