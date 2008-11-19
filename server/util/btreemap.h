/* 
   SSSD

   Service monitor

   Copyright (C) Stephen Gallagher	2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef BTREEMAP_H_
#define BTREEMAP_H_

typedef int (*btreemap_comparison_fn)(void *first, void *second);
struct btreemap;
int btreemap_search_key(struct btreemap *map, void *key, struct btreemap **node);
void *btreemap_get_value(struct btreemap *map, void *key);
int btreemap_set_value(struct btreemap **map, void *key, void *value,
                       btreemap_comparison_fn comparator);


#endif /*BTREEMAP_H_*/
