/*
    COLLECTION LIBRARY

    Implemenation of the collection library interface.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    Collection Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Collection Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Collection Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include "trace.h"

/* The collection should use the teal structures */
#include "collection_priv.h"
#include "collection.h"


/* Internal constants defined to denote actions that can be performed by find handler */
#define COLLECTION_ACTION_FIND       1
#define COLLECTION_ACTION_DEL        2
#define COLLECTION_ACTION_UPDATE     3
#define COLLECTION_ACTION_GET        4


/* Special internal error code to indicate that collection search was interrupted */
#define EINTR_INTERNAL 10000


/* Potential subjest for management with libtools */
#define DATE_FORMAT "%c"

#define TIME_ARRAY_SIZE 100


/* Struct used for passing parameter for update operation */
struct update_property {
        int type;
        void *data;
        int length;
        int found;
};

/* Dummy structure */
struct collection_item dummy = { NULL, "", 0, COL_TYPE_END, 0, NULL };

/******************** FUNCTION DECLARATIONS ****************************/

/* Have to declare those due to function cross referencing */
static int find_item_and_do(struct collection_item *ci,
                            char *property_to_find,
                            int type,
                            int mode_flags,
                            item_fn item_handler,
                            void *custom_data,
                            int action);

/* Traverse callback for find & delete function */
static int act_traverse_handler(struct collection_item *head,
                                struct collection_item *previous,
                                struct collection_item *current,
                                void *passed_traverse_data,
                                item_fn user_item_handler,
                                void *custom_data,
                                int *stop);

/* Traverse callback signature */
typedef int (*internal_item_fn)(struct collection_item *head,
                                struct collection_item *previous,
                                struct collection_item *current,
                                void *traverse_data,
                                item_fn user_item_handler,
                                void *custom_data,
                                int *stop);

/******************** SUPPLIMENTARY FUNCTIONS ****************************/


/* BASIC OPERATIONS */
/* Function that checks if property can be added */
static int validate_property(char *property)
{
    TRACE_FLOW_STRING("validate_property","Entry point.");
    /* Only alpha numeric characters are allowed in names of the properties */
    int invalid = 0;
    char *check;

    check = property;
    while(*check != '\0') {
        if((!isalnum((int)(*check))) && (!ispunct((int)(*check)))) {
            invalid = 1;
            break;
        }
        check++;
    }
    TRACE_FLOW_NUMBER("validate_property. Returning ",invalid);
    return invalid;
}



/* Function that cleans the item */
static void delete_item(struct collection_item *item)
{
    TRACE_FLOW_STRING("delete_item","Entry point.");

    if(item == (struct collection_item *)NULL) return;

    if(item->property != NULL) free(item->property);
    if(item->data != NULL) free(item->data);

    free(item);

    TRACE_FLOW_STRING("delete_item","Exit.");
}

/* A generic function to allocate a property item */
static int allocate_item(struct collection_item **ci,char *property,void *item_data,int length, int type)
{
    struct collection_item *item = NULL;
    int error = 0;
    errno = 0;

    TRACE_FLOW_STRING("allocate_item","Entry point.");
    TRACE_INFO_NUMBER("Will be using type:",type);

    /* Check the length */
    if(length >= COL_MAX_DATA) {
        TRACE_ERROR_STRING("allocate_item","Data to long.");
        return EMSGSIZE;
    }

    if(validate_property(property)) {
        TRACE_ERROR_STRING("Invalid chracters in the property name",property);
        return EINVAL;
    }

    /* Allocate memory for the structure */
    item = (struct collection_item *)(malloc(sizeof(struct collection_item)));
    if(item == (struct collection_item *)(NULL))  {
        error = errno;
        TRACE_ERROR_STRING("allocate_item","Malloc failed.");
        return error;
    }

    /* After we initialize "next" we can use delete_item() in case of error */
    item->next = (struct collection_item *)(NULL);

    /* Copy property */
    item->property = strdup(property);
    if(item->property == NULL) {
        error = errno;
        TRACE_ERROR_STRING("allocate_item","Failed to dup property.");
        delete_item(item);
        return error;
    }

    item->property_len = strlen(item->property);

    /* Deal with data */
    item->data = malloc(length);
    if(item->data == NULL) {
        TRACE_ERROR_STRING("allocate_item","Failed to dup data.");
        delete_item(item);
        return errno;
    }
    memcpy(item->data,item_data,length);

    /* Deal with other properties of the item */
    TRACE_INFO_NUMBER("About to set type to:",type);
    item->type = type;
    item->length = length;

    /* Make sure that data is NULL terminated in case of string */
    if(type == COL_TYPE_STRING) *(((char *)(item->data))+length-1) = '\0';

    *ci = item;

    TRACE_INFO_STRING("Item property",item->property);
    TRACE_INFO_NUMBER("Item property type",item->type);
    TRACE_INFO_NUMBER("Item data length",item->length);
    TRACE_FLOW_STRING("allocate_item","Success exit.");
    return 0;
}

/* Add item to the end of collection */
/* Can add itself to itself - nice...*/
static int add_item_to_collection(struct collection_item *collection,struct collection_item *item)
{
    struct collection_header *header;

    TRACE_FLOW_STRING("add_item_to_collection","Entry point.");

    if(collection == (struct collection_item *)(NULL)) {
        TRACE_INFO_STRING("add_item_to_collection","Collection accepting is NULL");
        if((item != (struct collection_item *)(NULL)) &&
           (item->type == COL_TYPE_COLLECTION)) {
            /* This is a special case of self creation */
            TRACE_INFO_STRING("add_item_to_collection","Adding header item to new collection.");
            collection = item;
        }
    }

    /* We can add items only to collections */
    if(collection->type != COL_TYPE_COLLECTION) {
        TRACE_ERROR_STRING("add_item_to_collection","Attempt to add item to non collection.");
        TRACE_ERROR_STRING("Collection name:",collection->property);
        TRACE_ERROR_NUMBER("Collection type:",collection->type);
        return EINVAL;
    }

    header = (struct collection_header *)(collection->data);

    /* Link new item to the last item in the list if there any */
    if(header->last != (struct collection_item *)(NULL)) (header->last)->next = item;

    /* Make sure we save a new last element */
    header->last = item;
    header->count++;

    TRACE_INFO_STRING("Collection:",collection->property);
    TRACE_INFO_STRING("Just added item is:",item->property);
    TRACE_INFO_NUMBER("Item type.",item->type);
    TRACE_INFO_NUMBER("Number of items in collection now is.",header->count);

    TRACE_FLOW_STRING("add_item_to_collection","Success exit.");
    return EOK;
}


/* TRAVERSE HANDLERS */

/* Special handler to just set a flag if the item is found */
inline static int is_in_item_handler(char *property,
                                     int property_len,
                                     int type,
                                     void *data,
                                     int length,
                                     void *found,
                                     int *dummy)
{
    TRACE_FLOW_STRING("is_in_item_handler","Entry.");
    TRACE_INFO_STRING("Property:",property);
    TRACE_INFO_NUMBER("Property length:",property_len);
    TRACE_INFO_NUMBER("Type:",type);
    TRACE_INFO_NUMBER("Length:",length);

    *((int *)(found)) = COL_MATCH;

    TRACE_FLOW_STRING("is_in_item_handler","Success Exit.");

    return EOK;
}

/* Special handler to retrieve the sub collection */
inline static int get_subcollection(char *property,
                                    int property_len,
                                    int type,
                                    void *data,
                                    int length,
                                    void *found,
                                    int *dummy)
{
    TRACE_FLOW_STRING("get_subcollection","Entry.");
    TRACE_INFO_STRING("Property:",property);
    TRACE_INFO_NUMBER("Property length:",property_len);
    TRACE_INFO_NUMBER("Type:",type);
    TRACE_INFO_NUMBER("Length:",length);

    *((struct collection_item **)(found)) = *((struct collection_item **)(data));

    TRACE_FLOW_STRING("get_subcollection","Success Exit.");

    return EOK;

}


/* ADD PROPERTY */

/* Add a single property to a collection. Returns a pointer to a newly allocated property */
static struct collection_item *add_property(struct collection_item *collection,
                                            char *subcollection,
                                            char *property,
                                            void *item_data,
                                            int length,
                                            int type,
                                            int *error)
{
    struct collection_item *item = (struct collection_item *) NULL;
    struct collection_item *acceptor = (struct collection_item *)(NULL);

    TRACE_FLOW_STRING("add_property","Entry.");
    /* Allocate item */

    TRACE_INFO_NUMBER("Property type to add",type);
    *error = allocate_item(&item,property,item_data,length, type);
    if(*error) return (struct collection_item *)(NULL);

    TRACE_INFO_STRING("Created item:",item->property);
    TRACE_INFO_NUMBER("Item has type:",item->type);

    /* Add item to collection */
    if(subcollection == NULL) acceptor = collection;
    else {
        TRACE_INFO_STRING("Subcollection id not null, searching",subcollection);
        *error = find_item_and_do(collection, subcollection, COL_TYPE_COLLECTIONREF,
                                  COL_TRAVERSE_DEFAULT,
                                  get_subcollection,(void *)(&acceptor),COLLECTION_ACTION_FIND);
        if(*error) {
            TRACE_ERROR_NUMBER("Search for subcollection returned error:",*error);
            delete_item(item);
            return (struct collection_item *)(NULL);
        }

        if(acceptor == (struct collection_item *)(NULL)) {
            TRACE_ERROR_STRING("Search for subcollection returned NULL pointer","");
            delete_item(item);
            *error=ENOENT;
            return (struct collection_item *)(NULL);
        }

    }
    *error = add_item_to_collection(acceptor,item);
    if(*error) {
        TRACE_ERROR_NUMBER("Failed to add item to collection error:",*error);
        delete_item(item);
        return (struct collection_item *)(NULL);
    }

    TRACE_FLOW_STRING("add_property","Success Exit.");
    return item;
}

/* CLEANUP */

/* Cleans the collection tree including current item. */
/* After the execution passed in variable should not be used - memory is gone!!! */
static void delete_collection(struct collection_item *ci)
{
    struct collection_item *other_collection;

    TRACE_FLOW_STRING("delete_collection","Entry.");

    if(ci == (struct collection_item *)(NULL)) {
        TRACE_FLOW_STRING("delete_collection","Nothing to do Exit.");
        return;
    }

    TRACE_INFO_STRING("Real work to do","");

    delete_collection(ci->next);

    /* Handle external or embedded collection */
    if(ci->type == COL_TYPE_COLLECTIONREF)  {
        /* Our data is a pointer to a whole external collection so dereference it or delete */
        other_collection = *((struct collection_item **)(ci->data));
        destroy_collection(other_collection);
    }

    /* Delete this item */
    delete_item(ci);
    TRACE_FLOW_STRING("delete_collection","Exit.");
}


/* NAME MANAGEMENT - used by search */

/* Internal data structures used for search */

struct path_data {
    char *name;
    int length;
    struct path_data *previous_path;
};

struct find_name {
    char *name_to_find;
    int name_len_to_find;
    int type_to_match;
    char *given_name;
    int given_len;
    struct path_data *current_path;
    int action;
};

/* Create a new name */
static int create_path_data(struct path_data **name_path,
                            char *name, int length,
                            char *property, int property_len)
{
    int error = EOK;
    struct path_data *new_name_path;

    TRACE_FLOW_STRING("create_path_data","Entry.");

    TRACE_INFO_STRING("Constructing path from name:",name);
    TRACE_INFO_STRING("Constructing path from property:",property);

    /* Allocate structure */
    errno = 0;
    new_name_path = (struct path_data *)(malloc(sizeof(struct path_data)));
    if(new_name_path == (struct path_data *)(NULL)) return errno;

    new_name_path->name=malloc(length+property_len+2);
    if(new_name_path->name == NULL) {
        error = errno;
        TRACE_ERROR_NUMBER("Failed to allocate memory for new path name. Errno",error);
        free((void *)(new_name_path));
        return error;
    }

    /* Construct the new name */
    new_name_path->length = 0;

    if(length > 0) {
        memcpy(new_name_path->name,name,length);
        new_name_path->length = length;
        *(new_name_path->name+new_name_path->length) = '.';
        new_name_path->length++;
        *(new_name_path->name+new_name_path->length) = '\0';
        TRACE_INFO_STRING("Name so far:",new_name_path->name);
        TRACE_INFO_NUMBER("Len so far:",new_name_path->length);
    }
    memcpy(new_name_path->name+new_name_path->length,property,property_len);
    new_name_path->length += property_len;
    *(new_name_path->name + new_name_path->length) = '\0';

    /* Link to the chain */
    new_name_path->previous_path = *name_path;
    *name_path = new_name_path;

    TRACE_INFO_STRING("Constructed path",new_name_path->name);


    TRACE_FLOW_NUMBER("create_path_data. Returning:",error);
    return error;
}

/* Matching item name and type */
static int match_item(struct collection_item *current,
                      struct find_name *traverse_data)
{

    char *find_str;
    char *start;
    char *data_str;

    TRACE_FLOW_STRING("match_item","Entry");

    if(traverse_data->type_to_match & current->type) {
        /* Check if there is any value to match */
        if((traverse_data->name_to_find == NULL) ||
           (*(traverse_data->name_to_find) == '\0')) {
            TRACE_INFO_STRING("match_item","Returning MATCH because there is no search criteria!");
            return COL_MATCH;
        }

        /* Start comparing the two strings from the end */
        find_str = traverse_data->name_to_find + traverse_data->name_len_to_find;
        start = current->property;
        data_str = start + current->property_len;

        TRACE_INFO_STRING("Searching for:",traverse_data->name_to_find);
        TRACE_INFO_STRING("Item name:",current->property);
        TRACE_INFO_STRING("Current path:",traverse_data->current_path->name);
        TRACE_INFO_NUMBER("Searching:",toupper(*find_str));
        TRACE_INFO_NUMBER("Have:",toupper(*data_str));

        /* We start pointing to 0 so the loop will be executed at least once */
        while(toupper(*data_str) == toupper(*find_str)) {

            TRACE_INFO_STRING("Loop iteration:","");

            if(data_str == start) {
                if(find_str > traverse_data->name_to_find) {
                    if(*(find_str-1) == '.') {
                        /* We matched the property but the search string is longer */
                        /* so we need to continue matching */
                        TRACE_INFO_STRING("match_item","Need to continue matching");
                        start = traverse_data->current_path->name;
                        data_str = start + traverse_data->current_path->length - 1;
                        find_str-=2;
                        continue;
                    }
                    else {
                        TRACE_INFO_STRING("match_item","Returning NO match!");
                        return COL_NOMATCH;
                    }
                }
                else {
                    TRACE_INFO_STRING("match_item","Returning MATCH!");
                    return COL_MATCH;
                }
            }
            else if((find_str == traverse_data->name_to_find) &&
                    (*(data_str-1) == '.')) return COL_MATCH;

            data_str--;
            find_str--;
             TRACE_INFO_NUMBER("Searching:",toupper(*find_str));
            TRACE_INFO_NUMBER("Have:",toupper(*data_str));

        }
    }

    TRACE_FLOW_STRING("match_item","Returning NO match!");
    return COL_NOMATCH;

}

/* Function to delete the data that contains search path */
static void delete_path_data(struct path_data *path)
{
    TRACE_FLOW_STRING("delete_path_data","Entry.");

    if(path!= (struct path_data *)(NULL)) {
        TRACE_INFO_STRING("delete_path_data","Item to delete exits.");
        if(path->previous_path != (struct path_data *)(NULL)) {
            TRACE_INFO_STRING("delete_path_data","But previous item to delete exits to. Nesting.");
            delete_path_data(path->previous_path);
        }
        if(path->name != NULL) {
            TRACE_INFO_STRING("delete_path_data Deleting path:",path->name);
            free(path->name);
        }
        TRACE_INFO_STRING("delete_path_data","Deleting path element");
        free((void *)(path));
    }
    TRACE_FLOW_STRING("delete_path_data","Exit");
}


/* MAIN TRAVERSAL FUNCTION */

/* Internal function to walk collection */
/* For each item walked it will call traverse handler.
   Traverse handler accepts: current item,
   user provided item handler and user provided custom data. */
/* See below defferent traverse handlers for different cases */
static int walk_items(struct collection_item *ci,
                      int mode_flags,
                      internal_item_fn traverse_handler,
                      void *traverse_data,
                      item_fn user_item_handler,
                      void *custom_data) {

    struct collection_item *current;
    struct collection_item *parent;
    struct collection_item *sub;
    int stop = 0;
    int error = EOK;

    TRACE_FLOW_STRING("walk_items","Entry.");
    TRACE_INFO_NUMBER("Mode flags:",mode_flags);

    current = ci;

    while(current != (struct collection_item *)(NULL)) {

        TRACE_INFO_STRING("Processing item:",current->property);
        TRACE_INFO_NUMBER("Item type:",current->type);

        if(current->type == COL_TYPE_COLLECTIONREF) {

            TRACE_INFO_STRING("Subcollection:",current->property);

            if((mode_flags & COL_TRAVERSE_IGNORE) == 0) {

                TRACE_INFO_STRING("Subcollection is not ignored.","");

                /* We are not ignoring sub collections */
                error = traverse_handler(ci,parent,current,traverse_data,user_item_handler,custom_data,&stop);
                if(stop != 0) {
                    TRACE_INFO_STRING("Traverse handler returned STOP.","");
                    error = EINTR_INTERNAL;
                }
                /* Check what error we got */
                if(error == EINTR_INTERNAL) {
                    TRACE_FLOW_NUMBER("Internal error - means we are stopping.",error);
                    return error;
                }
                else if(error) {
                    TRACE_ERROR_NUMBER("Traverse handler returned error.",error);
                    return error;
                }

                if((mode_flags & COL_TRAVERSE_ONELEVEL) == 0) {
                    TRACE_INFO_STRING("Before diving into sub collection","");
                    sub = *((struct collection_item **)(current->data));
                    TRACE_INFO_STRING("Sub collection name",sub->property);
                    TRACE_INFO_NUMBER("Header type",sub->type);
                    /* We need to go into sub collections */
                    error = walk_items(sub, mode_flags,traverse_handler,traverse_data,
                                       user_item_handler, custom_data);
                    TRACE_INFO_STRING("Returned from sub collection processing","");
                    TRACE_INFO_STRING("Done processing item:",current->property);
                    TRACE_INFO_NUMBER("Done processing item type:",current->type);

                }
            }
        }
        else
            /* Call handler then move on */
            error = traverse_handler(ci,parent,current,traverse_data,user_item_handler,custom_data,&stop);

        /* If we are stopped - return EINTR_INTERNAL */
        if(stop != 0) {
            TRACE_INFO_STRING("Traverse handler returned STOP.","");
            error = EINTR_INTERNAL;
        }
        /* Check what error we got */
        if(error == EINTR_INTERNAL) {
            TRACE_FLOW_NUMBER("Internal error - means we are stopping.",error);
            return error;
        }
        else if(error) {
            TRACE_ERROR_NUMBER("Traverse handler returned error.",error);
            return error;
        }

        parent = current;
        current = current->next;

    }

    TRACE_INFO_STRING("Out of loop","");

    if((mode_flags & COL_TRAVERSE_END) != 0) {
        TRACE_INFO_STRING("About to do the special end collection invocation of handler","");
        error = traverse_handler(ci,parent,current,traverse_data,user_item_handler,custom_data,&stop);
    }

    TRACE_FLOW_NUMBER("walk_items. Returns: ",error);
    return error;
}


/* ACTION */

/* Find an item by property name and perform an action on it. */
/* No pattern matching supported in the first implementation. */
/* To refer to child properties use dotted notatation like this: */
/* parent.child.subchild.subsubchild etc.  */
static int find_item_and_do(struct collection_item *ci,
                            char *property_to_find,
                            int type,
                            int mode_flags,
                            item_fn item_handler,
                            void *custom_data,
                            int action)
{

    int error = EOK;
    struct find_name *traverse_data = NULL;

    TRACE_FLOW_STRING("find_item_and_do","Entry.");

    /* Item handler is always required */
    if((item_handler == (item_fn)(NULL)) && (action ==COLLECTION_ACTION_FIND)) {
        TRACE_ERROR_NUMBER("No item handler - returning error!",EINVAL);
        return EINVAL;
    }

    /* Make sure that there is anything to search */
    type &= COL_TYPE_ANY;
    if((ci == (struct collection_item *)(NULL)) ||
       ((property_to_find == NULL) && (type == 0)) ||
       ((*property_to_find == '\0') && (type == 0))) {
        TRACE_ERROR_NUMBER("No item search criteria specified - returning error!",ENOKEY);
        return ENOKEY;
    }
    /* Prepare data for traversal */
    errno = 0;
    traverse_data= (struct find_name *)(malloc(sizeof(struct find_name)));
    if(traverse_data == (struct find_name *)(NULL)) {
        error = errno;
        TRACE_ERROR_NUMBER("Failed to allocate traverse data memory - returning error!",errno);
        return error;
    }

    TRACE_INFO_STRING("find_item_and_do","Filling in traverse data.");

    traverse_data->name_to_find = property_to_find;
    traverse_data->name_len_to_find = strlen(property_to_find);
    traverse_data->type_to_match = type;
    traverse_data->given_name = NULL;
    traverse_data->given_len = 0;
    traverse_data->current_path = (struct path_data *)(NULL);
    traverse_data->action = action;

    mode_flags |= COL_TRAVERSE_END;

    TRACE_INFO_STRING("find_item_and_do","About to walk the tree.");
    TRACE_INFO_NUMBER("Traverse flags",mode_flags);

    error = walk_items(ci, mode_flags, act_traverse_handler,
                       (void *)traverse_data, item_handler, custom_data);

    if(traverse_data->current_path != (struct path_data *)(NULL)) {
        TRACE_INFO_STRING("find_item_and_do","Path was not cleared - deleting");
        delete_path_data(traverse_data->current_path);
    }

    free((void *)(traverse_data));

    if((error) && (error != EINTR_INTERNAL)) {
        TRACE_ERROR_NUMBER("Walk items returned error. Returning: ",error);
        return error;
    }
    else {
        TRACE_FLOW_STRING("Walk items returned SUCCESS.","");
        return EOK;
    }
}

/* Function to replace data in the item */
static int update_current_item(struct collection_item *current,
                               struct update_property *update_data)
{
    TRACE_FLOW_STRING("update_current_item","Entry");

    /* If type is different or same but it is string or binary we need to replace the storage */
    if((current->type != update_data->type) ||
       ((current->type == update_data->type) &&
       ((current->type == COL_TYPE_STRING) || (current->type == COL_TYPE_BINARY)))) {
        TRACE_INFO_STRING("Replacing item data buffer","");
        free(current->data);
        current->data = malloc(update_data->length);
        if(current->data == NULL) {
            TRACE_ERROR_STRING("Failed to allocate memory","");
            current->length = 0;
            return ENOMEM;
        }
        current->length = update_data->length;
    }

    TRACE_INFO_STRING("Overwriting item data","");
    memcpy(current->data,update_data->data,current->length);
    current->type = update_data->type;

    if(current->type == COL_TYPE_STRING) *(((char *)(current->data))+current->length-1) = '\0';

    TRACE_FLOW_STRING("update_current_item","Exit");
    return EOK;
}

/* TRAVERSE CALLBACKS */

/* Traverse handler for simple traverse function */
/* Handler must be able to deal with NULL current item */
inline static int simple_traverse_handler(struct collection_item *head,
                                          struct collection_item *previous,
                                          struct collection_item *current,
                                          void *traverse_data,
                                          item_fn user_item_handler,
                                          void *custom_data,
                                          int *stop)
{
    int error = EOK;

    TRACE_FLOW_STRING("simple_traverse_handler","Entry.");

    if(current == (struct collection_item *)(NULL)) current = &dummy;

    error = user_item_handler(current->property,
                              current->property_len,
                              current->type,
                              current->data,
                              current->length,
                              custom_data,
                              stop);

    TRACE_FLOW_NUMBER("simple_traverse_handler. Returning:",error);
    return error;
}


/* Traverse callback for find & delete function */
static int act_traverse_handler(struct collection_item *head,
                                struct collection_item *previous,
                                struct collection_item *current,
                                void *passed_traverse_data,
                                item_fn user_item_handler,
                                void *custom_data,
                                int *stop)
{
    int error = EOK;
    struct find_name *traverse_data = NULL;
    char *name;
    int length;
    struct path_data *temp;
    struct collection_header *header;
    struct collection_item *other;
    char *property;
    int property_len;
    struct update_property *update_data;

    TRACE_FLOW_STRING("act_traverse_handler","Entry.");

    traverse_data = (struct find_name *)(passed_traverse_data);

    /* We can be called when current points to NULL */
    if(current==(struct collection_item *)(NULL)) {
        TRACE_INFO_STRING("act_traverse_handler","Special call at the end of the collection.");
        temp = traverse_data->current_path;
        traverse_data->current_path = temp->previous_path;
        temp->previous_path = (struct path_data *)(NULL);
        delete_path_data(temp);
        traverse_data->given_name = NULL;
        traverse_data->given_len = 0;
        TRACE_FLOW_NUMBER("Handling end of collection - removed path. Returning:", error);
        return error;
    }

    /* Create new path at the beginning of a new sub collection */
    if(current->type == COL_TYPE_COLLECTION) {

        TRACE_INFO_STRING("act_traverse_handler","Processing collection handle.");

        /* Create new path */
        if(traverse_data->current_path != (struct path_data *)(NULL)) {
            TRACE_INFO_STRING("Already have part of the path","");
            name = (traverse_data->current_path)->name;
            length = (traverse_data->current_path)->length;
            TRACE_INFO_STRING("Path:",name);
            TRACE_INFO_NUMBER("Path len:",length);
        }
        else {
            name = NULL;
            length = 0;
        }

        if(traverse_data->given_name != NULL) {
            property = traverse_data->given_name;
            property_len = traverse_data->given_len;
        }
        else {
            property = current->property;
            property_len = current->property_len;
        }

        TRACE_INFO_STRING("act_traverse_handler","About to create path data.");

        error = create_path_data(&(traverse_data->current_path),
                                 name, length, property,property_len);

        TRACE_INFO_NUMBER("create_path_data returned:", error);
        return error;
    }

    /* Handle the collection pointers */
    if(current->type == COL_TYPE_COLLECTIONREF) {
        traverse_data->given_name = current->property;
        traverse_data->given_len = current->property_len;
        TRACE_INFO_STRING("Saved given name:",traverse_data->given_name);
    }

    TRACE_INFO_STRING("Processing item with property:",current->property);

    /* Do here what we do with items */
    if(match_item(current,traverse_data)) {
        TRACE_INFO_STRING("Matched item:",current->property);
        switch(traverse_data->action) {
            case COLLECTION_ACTION_FIND:
                TRACE_INFO_STRING("It is a find action - calling handler.","");
                if(user_item_handler != (item_fn)(NULL)) {
                    /* Call user handler */
                    error = user_item_handler(current->property,
                                              current->property_len,
                                              current->type,
                                              current->data,
                                              current->length,
                                              custom_data,
                                              stop);

                    TRACE_INFO_NUMBER("Handler returned:",error);
                    TRACE_INFO_NUMBER("Handler set STOP to:",*stop);

                }
                break;
            case COLLECTION_ACTION_GET:
                TRACE_INFO_STRING("It is a get action.","");
                if(custom_data != NULL) *((struct collection_item **)(custom_data)) = current;
                break;
            case COLLECTION_ACTION_DEL:
                TRACE_INFO_STRING("It is a delete action.","");
                /* Make sure we tell the caller we found a match */
                if(custom_data != NULL) *(int *)(custom_data) = COL_MATCH;
                /* Dereference external collections */
                if(current->type == COL_TYPE_COLLECTIONREF) {
                    TRACE_INFO_STRING("Dereferencing a referenced collection.","");
                    other = *((struct collection_item **)(current->data));
                    header = (struct collection_header *)(other->data);
                    destroy_collection(other);
                }

                /* Adjust header of the collection */
                header = (struct collection_header *)(head->data);
                (header->count)--;
                if(current->next == (struct collection_item *)(NULL)) header->last = previous;

                /* Unlink and delete iteam */
                /* Previous can't be NULL here becuase we never delete header elements */
                previous->next = current->next;
                delete_item(current);
                TRACE_INFO_STRING("Did the delete of the item.","");
                break;
            case COLLECTION_ACTION_UPDATE:
                TRACE_INFO_STRING("It is an update action.","");
                if((current->type == COL_TYPE_COLLECTION) ||
                   (current->type == COL_TYPE_COLLECTIONREF)) {
                    TRACE_ERROR_STRING("Can't update collections it is an error for now","");
                    return EINVAL;
                }

                /* Make sure we tell the caller we found a match */
                if(custom_data != NULL) {
                    update_data = (struct update_property *) custom_data;
                    update_data-> found = COL_MATCH;
                    error = update_current_item(current, update_data);
                }
                else {
                    TRACE_ERROR_STRING("Error - update data is required","");
                    return EINVAL;
                }

                TRACE_INFO_STRING("Did the delete of the item.","");
                break;
            default:
                break;
        }
        /* Force interrupt if we found */
        *stop = 1;
    }

    TRACE_FLOW_NUMBER("act_traverse_handler returning",error);
    return error;
}


/* Traverse handler for copy function */
static int copy_traverse_handler(struct collection_item *head,
                                 struct collection_item *previous,
                                 struct collection_item *current,
                                 void *passed_traverse_data,
                                 item_fn user_item_handler,
                                 void *custom_data,
                                 int *stop)
{
    int error = EOK;
    struct collection_item *parent;
    struct collection_item *item;
    struct collection_item *new_collection = (struct collection_item *)(NULL);

    TRACE_FLOW_STRING("copy_traverse_handler","Entry.");

    parent = (struct collection_item *)(passed_traverse_data);

    /* Skip current element but rather work with next if it is not NULL */
    item = current->next;
    if(item == (struct collection_item *)(NULL)) return error;


    /* Check if this is a special case of sub collection */
    if(item->type == COL_TYPE_COLLECTIONREF) {
        TRACE_INFO_STRING("Found a subcollection we need to copy. Name:",item->property);

        error = copy_collection(&new_collection,
                                *((struct collection_item **)(item->data)),
                                item->property);
        if(error) {
            TRACE_ERROR_NUMBER("Copy subcollection returned error:",error);
            return error;
        }

        /* Add new item to a collection - all references are now sub collections */
        (void)add_property(parent,NULL,item->property,(void *)(&new_collection),
                           sizeof(struct collection_item **),
                           COL_TYPE_COLLECTIONREF, &error);
        if(error) {
            TRACE_ERROR_NUMBER("Add property returned error:",error);
            return error;
        }
    }
    else {
        (void)add_property(parent,NULL,item->property,item->data,
                           item->length,item->type,&error);
        if(error) {
            TRACE_ERROR_NUMBER("Add property returned error:",error);
            return error;
        }
    }

    TRACE_FLOW_NUMBER("copy_traverse_handler returning",error);
    return error;
}



/********************* MAIN INTERFACE FUNCTIONS ***********************************/


/* CREATE */

/* Function that creates an named collection of a given class*/
int create_collection(struct collection_item **ci,char *name, unsigned class)
{
    struct collection_item *handle = (struct collection_item *)(NULL);
    struct collection_header header;
    int error=EOK;

    TRACE_FLOW_STRING("create_collection","Entry.");

    /* Prepare header */
    header.last = (struct collection_item *)(NULL);
    header.reference_count = 1;
    header.count = 0;
    header.class = class;

    /* Create a collection type property */
    handle = add_property((struct collection_item *)(NULL),NULL,name,&header,sizeof(header), COL_TYPE_COLLECTION, &error);
    if(error) return error;

    *ci = handle;

    TRACE_FLOW_STRING("create_collection","Success Exit.");
    return 0;
}


/* DESTROY */

/* Function that destroys a collection */
void destroy_collection(struct collection_item *ci)
{
    struct collection_header *header;

    TRACE_FLOW_STRING("destroy_collection","Entry.");

    /* Do not try to delete NULL */
    if(ci == (struct collection_item *)(NULL)) return;

    /* You can delete only whole collection not a part of it */
    if(ci->type != COL_TYPE_COLLECTION) {
        TRACE_ERROR_STRING("Attempt to delete a non collection - BAD!","");
        TRACE_ERROR_NUMBER("Actual type is:",ci->type);
        return;
    }

    /* Collection can be referenced by other collection */
    header = (struct collection_header *)(ci->data);
    if(header->reference_count>1) {
        TRACE_INFO_STRING("Dereferencing a referenced collection.","");
        (header->reference_count)--;
        TRACE_INFO_NUMBER("Number after dereferencing.",header->reference_count);
    }
    else delete_collection(ci);

    TRACE_FLOW_STRING("destroy_collection","Exit.");
}


/* PROPERTIES */

/* Add a string property.
   If length equals 0, the length is determined based on the string.
   Lenght INCLUDES the terminating 0 */
inline int add_str_property(struct collection_item *ci,char *subcollection, char *property,char *string,int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_str_property","Entry.");

    if(length == 0) length = strlen(string) + 1;
    (void)(add_property(ci,subcollection,property,(void *)(string),length, COL_TYPE_STRING, &error));

    TRACE_FLOW_NUMBER("add_str_property returning",error);
    return error;
}

/* Add a binary property. */
inline int add_binary_property(struct collection_item *ci,char *subcollection, char *property,void *binary_data,int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_binary_property","Entry.");

    (void)(add_property(ci,subcollection,property,binary_data,length, COL_TYPE_BINARY, &error));

    TRACE_FLOW_NUMBER("add_binary_property returning",error);
    return error;
}

/* Add an int property. */
inline int add_int_property(struct collection_item *ci,char *subcollection, char *property,int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_int_property","Entry.");

    (void)(add_property(ci,subcollection,property,(void *)(&number),sizeof(int), COL_TYPE_INTEGER, &error));

    TRACE_FLOW_NUMBER("add_int_property returning",error);
    return error;
}

/* Add an unsigned int property. */
inline int add_unsigned_property(struct collection_item *ci,char *subcollection, char *property,unsigned int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_unsigned_property","Entry.");

    (void)(add_property(ci,subcollection,property,(void *)(&number),sizeof(int), COL_TYPE_UNSIGNED, &error));

    TRACE_FLOW_NUMBER("add_unsigned_property returning",error);
    return error;
}

/* Add an long property. */
inline int add_long_property(struct collection_item *ci,char *subcollection, char *property,long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_long_property","Entry.");

    (void)(add_property(ci,subcollection,property,(void *)(&number),sizeof(long), COL_TYPE_LONG, &error));

    TRACE_FLOW_NUMBER("add_long_property returning",error);
    return error;
}

/* Add an unsigned long property. */
inline int add_ulong_property(struct collection_item *ci,char *subcollection, char *property,unsigned long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_ulong_property","Entry.");

    (void)(add_property(ci,subcollection,property,(void *)(&number),sizeof(long), COL_TYPE_ULONG, &error));

    TRACE_FLOW_NUMBER("add_ulong_property returning",error);
    return error;
}

/* Add a double property. */
inline int add_double_property(struct collection_item *ci,char *subcollection, char *property,double number)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_double_property","Entry.");

    (void)(add_property(ci,subcollection,property,(void *)(&number),sizeof(double), COL_TYPE_DOUBLE, &error));

    TRACE_FLOW_NUMBER("add_double_property returning",error);
    return error;
}

/* Add a bool property. */
inline int add_bool_property(struct collection_item *ci,char *subcollection, char *property,unsigned char logical)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_bool_property","Entry.");

    (void)(add_property(ci,subcollection,property,(void *)(&logical),sizeof(unsigned char), COL_TYPE_BOOL, &error));

    TRACE_FLOW_NUMBER("add_bool_property returning",error);
    return error;
}

/* A function to add a property */
inline int add_any_property(struct collection_item *ci,
                            char *subcollection,
                            char *property,
                            int type,
                            void *data,
                            int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("add_any_property","Entry.");

    (void)(add_property(ci,subcollection,property,data,length, type, &error));

    TRACE_FLOW_NUMBER("add_any_property returning",error);
    return error;
}

/* Add a string property.
   If length equals 0, the length is determined based on the string.
   Lenght INCLUDES the terminating 0 */
inline int add_str_property_with_ref(struct collection_item *ci,char *subcollection,
                                     char *property,char *string,int length,
                                     struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_str_property_with_ref","Entry.");

    if(length == 0) length = strlen(string) + 1;
    item = add_property(ci,subcollection,property,(void *)(string),length, COL_TYPE_STRING, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_str_property_with_ref returning",error);
    return error;
}

/* Add a binary property. */
inline int add_binary_property_with_ref(struct collection_item *ci,char *subcollection,
                                        char *property,void *binary_data,int length,
                                        struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_binary_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,binary_data,length, COL_TYPE_BINARY, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_binary_property_with_ref returning",error);
    return error;
}

/* Add an int property. */
inline int add_int_property_with_ref(struct collection_item *ci,char *subcollection,
                                     char *property,int number,
                                     struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_int_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,(void *)(&number),sizeof(int), COL_TYPE_INTEGER, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_int_property_with_ref returning",error);
    return error;
}

/* Add an unsigned int property. */
inline int add_unsigned_property_with_ref(struct collection_item *ci,char *subcollection,
                                          char *property,unsigned int number,
                                          struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_unsigned_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,(void *)(&number),sizeof(int), COL_TYPE_UNSIGNED, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_unsigned_property_with_ref returning",error);
    return error;
}

/* Add an long property. */
inline int add_long_property_with_ref(struct collection_item *ci,char *subcollection,
                                      char *property,long number,
                                      struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_long_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,(void *)(&number),sizeof(long), COL_TYPE_LONG, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_long_property_with_ref returning",error);
    return error;
}

/* Add an unsigned long property. */
inline int add_ulong_property_with_ref(struct collection_item *ci,char *subcollection,
                                       char *property,unsigned long number,
                                       struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_ulong_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,(void *)(&number),sizeof(long), COL_TYPE_ULONG, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_ulong_property_with_ref returning",error);
    return error;
}

/* Add a double property. */
inline int add_double_property_with_ref(struct collection_item *ci,char *subcollection,
                                        char *property,double number,
                                        struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_double_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,(void *)(&number),sizeof(double), COL_TYPE_DOUBLE, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_double_property_with_ref returning",error);
    return error;
}

/* Add a bool property. */
inline int add_bool_property_with_ref(struct collection_item *ci,char *subcollection,
                                      char *property,unsigned char logical,
                                      struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_bool_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,(void *)(&logical),sizeof(unsigned char), COL_TYPE_BOOL, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_bool_property_with_ref returning",error);
    return error;
}

/* A function to add a property */
inline int add_any_property_with_ref(struct collection_item *ci,
                                     char *subcollection,
                                     char *property,
                                     int type,
                                     void *data,
                                     int length,
                                     struct collection_item **ref_ret)
{
    int error = EOK;
    struct collection_item *item;

    TRACE_FLOW_STRING("add_any_property_with_ref","Entry.");

    item = add_property(ci,subcollection,property,data,length, type, &error);

    if(ref_ret != (struct collection_item **)(NULL)) *ref_ret = item;

    TRACE_FLOW_NUMBER("add_any_property_with_ref returning",error);
    return error;
}



/* COPY */

/* Create a deep copy of the current collection. */
/* Referenced collections of the donor are copied as sub collections. */
int copy_collection(struct collection_item **collection_copy,
                    struct collection_item *collection_to_copy,
                    char *name_to_use) {

    int error = EOK;
    struct collection_item *new_collection = (struct collection_item *)(NULL);
    char *name;
    struct collection_header *header;

    TRACE_FLOW_STRING("copy_collection","Entry.");

    /* Determine what name to use */
    if(name_to_use != NULL) name = name_to_use;
    else name = collection_to_copy->property;

    header = (struct collection_header *)(collection_to_copy->data);

    /* Create a new collection */
    error = create_collection(&new_collection,name,header->class);
    if(error) {
        TRACE_ERROR_NUMBER("Create_cllection failed returning",error);
        return error;
    }

    error = walk_items(collection_to_copy, COL_TRAVERSE_ONELEVEL, copy_traverse_handler,
                       new_collection, NULL, NULL);

    if(!error) *collection_copy = new_collection;
    else destroy_collection(new_collection);

    TRACE_FLOW_NUMBER("copy_collection returning",error);
    return error;

}

/* EXTRACTION */

/* Extract collection */
int get_collection_reference(struct collection_item *ci,          /* High level collection */
                             struct collection_item **acceptor,   /* The pointer that will accept extracted handle */
                             char *collection_to_find)            /* Name to of the collection */
{
    struct collection_header *header;
    struct collection_item *subcollection = (struct collection_item *)(NULL);
    int error = EOK;

    TRACE_FLOW_STRING("get_collection_reference","Entry.");

    if((ci == (struct collection_item *)(NULL)) ||
       (ci->type != COL_TYPE_COLLECTION) ||
       (acceptor == (struct collection_item **)(NULL)) ||
       (collection_to_find == NULL)) {
        TRACE_ERROR_NUMBER("Invalid parameter - returning error",EINVAL);
        return EINVAL;
    }

    /* Find a sub collection */
    TRACE_INFO_STRING("We are given subcollection name - search it:",collection_to_find);
    error = find_item_and_do(ci,collection_to_find,COL_TYPE_COLLECTIONREF,
                             COL_TRAVERSE_DEFAULT,
                             get_subcollection,(void *)(&subcollection),COLLECTION_ACTION_FIND);
    if(error) {
        TRACE_ERROR_NUMBER("Search failed returning error",error);
        return error;
    }

    if(subcollection == (struct collection_item *)(NULL)) {
        TRACE_ERROR_STRING("Search for subcollection returned NULL pointer","");
        return ENOENT;
    }

    header = (struct collection_header *)(subcollection->data);
    TRACE_INFO_NUMBER("Count:",header->count);
    TRACE_INFO_NUMBER("Ref count:",header->reference_count);
    (header->reference_count)++;
    TRACE_INFO_NUMBER("Ref count after increment:",header->reference_count);
    *acceptor = subcollection;

    TRACE_FLOW_STRING("get_collection_reference","Success Exit.");
    return EOK;
}

/* Get collection - if current item is a reference get a real collection from it. */
int get_reference_from_item(struct collection_item *ci,
                            struct collection_item **acceptor)
{
    struct collection_header *header;
    struct collection_item *subcollection = (struct collection_item *)(NULL);

    TRACE_FLOW_STRING("get_reference_from_item","Entry.");

    if((ci == (struct collection_item *)(NULL)) ||
       (ci->type != COL_TYPE_COLLECTIONREF) ||
       (acceptor == (struct collection_item **)(NULL))) {
        TRACE_ERROR_NUMBER("Invalid parameter - returning error",EINVAL);
        return EINVAL;
    }

    subcollection = *((struct collection_item **)(ci->data));

    header = (struct collection_header *)(subcollection->data);
    TRACE_INFO_NUMBER("Count:",header->count);
    TRACE_INFO_NUMBER("Ref count:",header->reference_count);
    (header->reference_count)++;
    TRACE_INFO_NUMBER("Ref count after increment:",header->reference_count);
    *acceptor = subcollection;

    TRACE_FLOW_STRING("get_reference_from_item","Success Exit.");
    return EOK;
}

/* ADDITION */

/* Add collection to collection */
int add_collection_to_collection(
   struct collection_item *ci,                /* Collection handle to with we add another collection */
   char *sub_collection_name,                 /* Name of the sub collection to which
                                                 collection needs to be added as a property.
                                                 If NULL high level collection is assumed. */
   char *as_property,                         /* Name of the collection property.
                                                 If NULL, same property as the name of
                                                 the collection being added will be used. */
   struct collection_item *collection_to_add, /* Collection to add */
   int mode)                                  /* How this collection needs to be added */
{
    struct collection_item *acceptor = (struct collection_item *)(NULL);
    char *name_to_use;
    struct collection_header *header;
    struct collection_item *collection_copy;
    int error = EOK;

    TRACE_FLOW_STRING("add_collection_to_collection","Entry.");

    if((ci == (struct collection_item *)(NULL)) ||
       (ci->type != COL_TYPE_COLLECTION) ||
       (collection_to_add == (struct collection_item *)(NULL)) ||
       (collection_to_add->type != COL_TYPE_COLLECTION)) {
        /* Need to debug here */
        TRACE_ERROR_NUMBER("Missing parameter - returning error",EINVAL);
        return EINVAL;
    }

    if(sub_collection_name != NULL) {
        /* Find a sub collection */
        TRACE_INFO_STRING("We are given subcollection name - search it:",sub_collection_name);
        error = find_item_and_do(ci,sub_collection_name,COL_TYPE_COLLECTIONREF,
                                 COL_TRAVERSE_DEFAULT,
                                 get_subcollection,(void *)(&acceptor),COLLECTION_ACTION_FIND);
        if(error) {
            TRACE_ERROR_NUMBER("Search failed returning error",error);
            return error;
        }

        if(acceptor == (struct collection_item *)(NULL)) {
            TRACE_ERROR_STRING("Search for subcollection returned NULL pointer","");
            return ENOENT;
        }

    }
    else acceptor = ci;

    if(as_property != NULL)
        name_to_use = as_property;
    else
        name_to_use = collection_to_add->property;


    TRACE_INFO_STRING("Going to use name:",name_to_use);


    switch(mode) {
        case COL_ADD_MODE_REFERENCE:
            TRACE_INFO_STRING("We are adding a reference.","");
            TRACE_INFO_NUMBER("Type of the header element:",collection_to_add->type);
            TRACE_INFO_STRING("Header name we are adding.",collection_to_add->property);
            /* Create a pointer to external collection */
            /* For future thread safety: Transaction start -> */
            (void)(add_property(acceptor,NULL,name_to_use,(void *)(&collection_to_add),
                                sizeof(struct collection_item **),
                                COL_TYPE_COLLECTIONREF, &error));

            TRACE_INFO_NUMBER("Type of the header element after add_property:",collection_to_add->type);
            TRACE_INFO_STRING("Header name we just added.",collection_to_add->property);
            if(error) {
                TRACE_ERROR_NUMBER("Adding property failed with error:",error);
                return error;
            }
            header = (struct collection_header *)(collection_to_add->data);
            TRACE_INFO_NUMBER("Count:",header->count);
            TRACE_INFO_NUMBER("Ref count:",header->reference_count);
            (header->reference_count)++;
            TRACE_INFO_NUMBER("Ref count after increment:",header->reference_count);
            /* -> Transaction end */
            break;
        case COL_ADD_MODE_EMBED:
            TRACE_INFO_STRING("We are embedding the collection.","");
            /* First check if the passed in collection is referenced more than once */
            TRACE_INFO_NUMBER("Type of the header element we are adding:",collection_to_add->type);
            TRACE_INFO_STRING("Header name we are adding.",collection_to_add->property);
            TRACE_INFO_NUMBER("Type of the header element we are adding to:",acceptor->type);
            TRACE_INFO_STRING("Header name we are adding to.",acceptor->property);

            (void)(add_property(acceptor,NULL,name_to_use,(void *)(&collection_to_add),
                                sizeof(struct collection_item **),
                                COL_TYPE_COLLECTIONREF, &error));

            TRACE_INFO_NUMBER("Adding property returned:",error);
            break;

        case COL_ADD_MODE_CLONE:
            TRACE_INFO_STRING("We are cloning the collection.","");
            TRACE_INFO_STRING("Name we will use.",name_to_use);

            /* For future thread safety: Transaction start -> */
            error = copy_collection(&collection_copy, collection_to_add, name_to_use);
            if(error) return error;

            TRACE_INFO_STRING("We have a collection copy.", collection_copy->property);
            TRACE_INFO_NUMBER("Collection type.", collection_copy->type);
            TRACE_INFO_STRING("Acceptor collection.", acceptor->property);
            TRACE_INFO_NUMBER("Acceptor collection type.", acceptor->type);

            (void)(add_property(acceptor,NULL,name_to_use,(void *)(&collection_copy),
                                sizeof(struct collection_item **),
                                COL_TYPE_COLLECTIONREF, &error));

            /* -> Transaction end */
            TRACE_INFO_NUMBER("Adding property returned:",error);
            break;

        default: error = EINVAL;
    }

    TRACE_FLOW_NUMBER("add_collection_to_collection returning:",error);
    return error;
}

/* TRAVERSING */

/* Function to traverse the entire collection including optionally sub collections */
inline int traverse_collection(struct collection_item *ci,
                               int mode_flags,
                               item_fn item_handler,
                               void *custom_data)
{

    int error = EOK;
    TRACE_FLOW_STRING("traverse_collection","Entry.");

    error = walk_items(ci, mode_flags, simple_traverse_handler,
                       NULL, item_handler, custom_data);

    if((error != 0) && (error != EINTR_INTERNAL)) {
        TRACE_ERROR_NUMBER("Error walking tree",error);
        return error;
    }

    TRACE_FLOW_STRING("traverse_collection","Success exit.");
    return EOK;
}

/* CHECK */

/* Convenience function to check if specific property is in the collection */
inline int is_item_in_collection(struct collection_item *ci,
                                 char *property_to_find,
                                 int type,
                                 int mode_flags,
                                 int *found)
{
    int error;

    TRACE_FLOW_STRING("is_item_in_collection","Entry.");

    *found = COL_NOMATCH;
    error = find_item_and_do(ci,property_to_find,type,mode_flags,
                             is_in_item_handler,(void *)found,COLLECTION_ACTION_FIND);

    TRACE_FLOW_NUMBER("is_item_in_collection returning",error);
    return error;
}

/* SEARCH */
/* Search function. Looks up an item in the collection based on the property.
   Essentually it is a traverse function with spacial traversing logic.
 */
inline int get_item_and_do(struct collection_item *ci,       /* Collection to find things in */
                           char *property_to_find,           /* Name to match */
                           int type,                         /* Type filter */
                           int mode_flags,                   /* How to traverse the collection */
                           item_fn item_handler,             /* Function to call when the item is found */
                           void *custom_data)                /* Custom data passed around */
{
    int error = EOK;

    TRACE_FLOW_STRING("get_item_and_do","Entry.");

    error = find_item_and_do(ci,property_to_find,type,mode_flags,item_handler,custom_data,COLLECTION_ACTION_FIND);

    TRACE_FLOW_NUMBER("get_item_and_do returning",error);
    return error;
}


/* Get raw item */
inline int get_item(struct collection_item *ci,       /* Collection to find things in */
                    char *property_to_find,           /* Name to match */
                    int type,                         /* Type filter */
                    int mode_flags,                   /* How to traverse the collection */
                    struct collection_item **item)    /* Found item */
{

    int error = EOK;

    TRACE_FLOW_STRING("get_item","Entry.");

    error = find_item_and_do(ci,property_to_find,type,mode_flags,NULL,(void *)(item),COLLECTION_ACTION_GET);

    TRACE_FLOW_NUMBER("get_item returning",error);
    return error;
}

/* DELETE */
/* Delete property from the collection */
inline int delete_property(struct collection_item *ci,    /* Collection to find things in */
                           char *property_to_find,        /* Name to match */
                           int type,                      /* Type filter */
                           int mode_flags)                /* How to traverse the collection */
{
    int error = EOK;
    int found;

    TRACE_FLOW_STRING("delete_property","Entry.");
    found = COL_NOMATCH;

    error = find_item_and_do(ci,property_to_find,type,mode_flags,NULL,(void *)(&found),COLLECTION_ACTION_DEL);

    if((error == EOK) && (found == COL_NOMATCH)) error = ENOENT;
    TRACE_FLOW_NUMBER("delete_property returning",error);
    return error;
}

/* UPDATE */
/* Update property in the collection */
int update_property(struct collection_item *ci,    /* Collection to find things in */
                    char *property_to_find,        /* Name to match */
                    int type,                      /* Type of the passed in data */
                    void *new_data,                /* Pointer to the new data */
                    int length,                    /* Length of the data. For strings should include trailing 0 */
                    int mode_flags)                /* How to traverse the collection  */

{
    int error = EOK;
    struct update_property update_data;

    TRACE_FLOW_STRING("update_property","Entry.");
    update_data.type = type;
    update_data.data = new_data;
    update_data.length = length;
    update_data.found = COL_NOMATCH;

    error = find_item_and_do(ci,property_to_find,type,mode_flags,NULL,(void *)(&update_data),COLLECTION_ACTION_UPDATE);

    if((error == EOK) && (update_data.found == COL_NOMATCH)) error = ENOENT;
    TRACE_FLOW_NUMBER("update_property returning",error);
    return error;
}

/* Update a string property in the collection. Length should include the null terminating 0  */
inline int update_str_property(struct collection_item *ci,
                               char *property,
                               int mode_flags,
                               char *string,
                               int length)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_str_property","Entry.");

    if(length == 0) length = strlen(string) + 1;
    error =  update_property(ci,property, COL_TYPE_STRING, (void *)(string),length,mode_flags);

    TRACE_FLOW_NUMBER("update_str_property Returning",error);
    return error;
}

/* Update a binary property in the collection.  */
inline int update_binary_property(struct collection_item *ci,
                                  char *property,
                                  int mode_flags,
                                  void *binary_data,
                                  int length)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_binary_property","Entry.");

    error =  update_property(ci,property, COL_TYPE_BINARY, binary_data, length, mode_flags);

    TRACE_FLOW_NUMBER("update_binary_property Returning",error);
    return error;
}

/* Update an int property in the collection. */
inline int update_int_property(struct collection_item *ci,
                               char *property,
                               int mode_flags,
                               int number)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_int_property","Entry.");

    error =  update_property(ci,property, COL_TYPE_INTEGER, (void *)(&number), sizeof(int), mode_flags);

    TRACE_FLOW_NUMBER("update_int_property Returning",error);
    return error;
}

/* Update an unsigned int property. */
inline int update_unsigned_property(struct collection_item *ci,
                                    char *property,int mode_flags,
                                    unsigned int number)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_unsigned_property","Entry.");

    error =  update_property(ci,property, COL_TYPE_UNSIGNED, (void *)(&number), sizeof(unsigned int), mode_flags);

    TRACE_FLOW_NUMBER("update_unsigned_property Returning",error);
    return error;
}
/* Update a long property. */
inline int update_long_property(struct collection_item *ci,
                                char *property,
                                int mode_flags,
                                long number)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_long_property","Entry.");

    error =  update_property(ci,property, COL_TYPE_LONG, (void *)(&number), sizeof(long), mode_flags);

    TRACE_FLOW_NUMBER("update_long_property Returning",error);
    return error;

}

/* Update an unsigned long property. */
inline int update_ulong_property(struct collection_item *ci,
                                 char *property,
                                 int mode_flags,
                                 unsigned long number)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_ulong_property","Entry.");

    error =  update_property(ci,property, COL_TYPE_ULONG, (void *)(&number), sizeof(unsigned long), mode_flags);

    TRACE_FLOW_NUMBER("update_ulong_property Returning",error);
    return error;
}

/* Update a double property. */
inline int update_double_property(struct collection_item *ci,
                                  char *property,
                                  int mode_flags,
                                  double number)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_double_property","Entry.");

    error =  update_property(ci,property, COL_TYPE_DOUBLE, (void *)(&number), sizeof(double), mode_flags);

    TRACE_FLOW_NUMBER("update_double_property Returning",error);
    return error;
}

/* Update a bool property. */
inline int update_bool_property(struct collection_item *ci,
                                char *property,
                                int mode_flags,
                                unsigned char logical)
{
    int error = EOK;
    TRACE_FLOW_STRING("update_bool_property","Entry.");

    error =  update_property(ci,property, COL_TYPE_BOOL, (void *)(&logical), sizeof(unsigned char), mode_flags);

    TRACE_FLOW_NUMBER("update_bool_property Returning",error);
    return error;
}

/* Function to modify the item */
int modify_item(struct collection_item *item,
                char *property,
                int type,
                void *data,
                int length)
{
    TRACE_FLOW_STRING("modify_item","Entry");

    if((item == (struct collection_item *)(NULL)) ||
       (item->type == COL_TYPE_COLLECTION) ||
       (item->type == COL_TYPE_COLLECTIONREF)) {
        TRACE_ERROR_NUMBER("Invalid argument or invalid argument type",EINVAL);
        return EINVAL;
    }

    if(property != NULL) {
        free(item->property);
        item->property=strdup(property);
        if(item->property == NULL) {
            TRACE_ERROR_STRING("Failed to allocate memory","");
            return ENOMEM;
        }
    }

    /* If type is different or same but it is string or binary we need to replace the storage */
    if((item->type != type) ||
       ((item->type == type) &&
       ((item->type == COL_TYPE_STRING) || (item->type == COL_TYPE_BINARY)))) {
        TRACE_INFO_STRING("Replacing item data buffer","");
        free(item->data);
        item->data = malloc(length);
        if(item->data == NULL) {
            TRACE_ERROR_STRING("Failed to allocate memory","");
            item->length = 0;
            return ENOMEM;
        }
        item->length = length;
    }


    TRACE_INFO_STRING("Overwriting item data","");
    memcpy(item->data,data,item->length);
    item->type = type;

    if(item->type == COL_TYPE_STRING) *(((char *)(item->data))+item->length-1) = '\0';

    TRACE_FLOW_STRING("modify_item","Exit");
    return EOK;
}


/* Convinience functions that wrap modify_item(). */
/* Modify item data to be str */
inline int modify_str_item(struct collection_item *item,
                           char *property,
                           char *string,
                           int length)
{
    int len;
    int error;

    TRACE_FLOW_STRING("modify_str_item","Entry");

    if(length != 0) len = length;
    else len = strlen(string) + 1;

    error = modify_item(item,property,COL_TYPE_STRING,(void *)string,len);

    TRACE_FLOW_STRING("modify_str_item","Exit");
    return error;
}

/* Modify item data to be binary */
inline int modify_binary_item(struct collection_item *item,
                              char *property,
                              void *binary_data,
                              int length)
{
    int error;

    TRACE_FLOW_STRING("modify_binary_item","Entry");

    error = modify_item(item,property,COL_TYPE_BINARY,binary_data,length);

    TRACE_FLOW_STRING("modify_binary_item","Exit");
    return error;
}

/* Modify item data to be bool */
inline int modify_bool_item(struct collection_item *item,
                            char *property,
                            unsigned char logical)
{
    int error;

    TRACE_FLOW_STRING("modify_bool_item","Entry");

    error = modify_item(item,property,COL_TYPE_BOOL,(void *)(&logical),1);

    TRACE_FLOW_STRING("modify_bool_item","Exit");
    return error;
}

/* Modify item data to be int */
inline int modify_int_item(struct collection_item *item,
                           char *property,
                           int number)
{
    int error;

    TRACE_FLOW_STRING("modify_int_item","Entry");

    error = modify_item(item,property,COL_TYPE_INTEGER,(void *)(&number),sizeof(int));

    TRACE_FLOW_STRING("modify_int_item","Exit");
    return error;
}

/* Modify item data to be long */
inline int modify_long_item(struct collection_item *item,
                            char *property,
                            long number)
{
    int error;

    TRACE_FLOW_STRING("modify_long_item","Entry");

    error = modify_item(item,property,COL_TYPE_LONG,(void *)(&number),sizeof(long));

    TRACE_FLOW_STRING("modify_long_item","Exit");
    return error;
}

/* Modify item data to be unigned long */
inline int modify_ulong_item(struct collection_item *item,
                             char *property,
                             unsigned long number)
{
    int error;

    TRACE_FLOW_STRING("modify_ulong_item","Entry");

    error = modify_item(item,property,COL_TYPE_ULONG,(void *)(&number),sizeof(unsigned long));

    TRACE_FLOW_STRING("modify_ulong_item","Exit");
    return error;
}

inline int modify_unsigned_item(struct collection_item *item,
                                char *property,
                                unsigned number)
{
    int error;

    TRACE_FLOW_STRING("modify_unsigned_item","Entry");

    error = modify_item(item,property,COL_TYPE_UNSIGNED,(void *)(&number),sizeof(unsigned));

    TRACE_FLOW_STRING("modify_unsigned_item","Exit");
    return error;
}

inline int modify_double_item(struct collection_item *item,
                              char *property,
                              double number)
{
    int error;

    TRACE_FLOW_STRING("modify_double_item","Entry");

    error = modify_item(item,property,COL_TYPE_DOUBLE,(void *)(&number),sizeof(double));

    TRACE_FLOW_STRING("modify_double_item","Exit");
    return error;
}


/* Grow iteration stack */
static int grow_stack(struct collection_iterator *iterator, unsigned desired)
{
    int grow_by = 0;
    struct collection_item **temp;

    TRACE_FLOW_STRING("grow_stack","Entry.");

    if(desired > iterator->stack_size) {
        grow_by = (((desired - iterator->stack_size) / STACK_DEPTH_BLOCK) + 1) * STACK_DEPTH_BLOCK;
        errno = 0;
        temp = (struct collection_item **)(realloc(iterator->stack,grow_by * sizeof(struct collection_item *)));
        if(temp == (struct collection_item **)(NULL)) {
            TRACE_ERROR_NUMBER("Failed to allocate memory",ENOMEM);
            return ENOMEM;
        }
        iterator->stack = temp;
        iterator->stack_size += grow_by;
    }
    TRACE_FLOW_STRING("grow_stack","Exit.");
    return EOK;
}



/* Bind iterator to a collection */
int bind_iterator(struct collection_iterator **iterator,
                  struct collection_item *ci,
                  int mode_flags)
{
    int error;
    struct collection_header *header;
    struct collection_iterator *iter = (struct collection_iterator *)(NULL);

    TRACE_FLOW_STRING("bind_iterator","Entry.");

    /* Do some argument checking first */
    if((iterator == (struct collection_iterator **)(NULL)) ||
       (ci == (struct collection_item *)(NULL))) {
        TRACE_ERROR_NUMBER("Invalid parameter.",EINVAL);
        return EINVAL;
    }

    iter = (struct collection_iterator *)malloc(sizeof(struct collection_iterator));
    if(iter == (struct collection_iterator *)(NULL)) {
        TRACE_ERROR_NUMBER("Error allocating memory for the iterator.",ENOMEM);
        return ENOMEM;
    }

    /* Allocate memory for the stack */
    iter->stack = (struct collection_item **)(NULL);
    iter->stack_size = 0;
    iter->stack_depth = 0;
    iter->flags = mode_flags;

    /* Allocate memory for stack */
    error = grow_stack(iter,1);
    if(error) {
        free(iter);
        TRACE_ERROR_NUMBER("Error growing stack.",error);
        return error;
    }

    /* Make sure that we tie iterator to the collection */
    header = (struct collection_header *)(ci->data);
    (header->reference_count)++;
    iter->top = ci;
    *(iter->stack) = ci;
    iter->stack_depth++;

    *iterator = iter;

    TRACE_FLOW_STRING("bind_iterator","Exit");
    return EOK;
}

/* Stop processing this subcollection and move to the next item in the collection 'level' levels up.*/
inline int iterate_up(struct collection_iterator *iterator, int level)
{
    TRACE_FLOW_STRING("iterate_up","Entry");

    if((iterator == (struct collection_iterator *)(NULL)) ||
       (level >= iterator->stack_depth)) {
        TRACE_ERROR_NUMBER("Invalid parameter.",EINVAL);
        return EINVAL;
    }

    TRACE_INFO_NUMBER("Going up:",level);

    iterator->stack_depth--;

    TRACE_INFO_NUMBER("Stack depth at the end:",iterator->stack_depth);
    TRACE_FLOW_STRING("iterate_up","Exit");
    return EOK;
}
/* How deep are we relative to the top level.*/
inline int get_iterator_depth(struct collection_iterator *iterator, int *depth)
{
    TRACE_FLOW_STRING("iterate_up","Entry");

    if((iterator == (struct collection_iterator *)(NULL)) ||
       (depth == (int *)(NULL))) {
        TRACE_ERROR_NUMBER("Invalid parameter.",EINVAL);
        return EINVAL;
    }

    *depth = iterator->stack_depth -1;

    TRACE_INFO_NUMBER("Stack depth at the end:",iterator->stack_depth);
    TRACE_FLOW_STRING("iterate_up","Exit");
    return EOK;
}


/* Unbind the iterator from the collection */
inline void unbind_iterator(struct collection_iterator *iterator)
{
    TRACE_FLOW_STRING("unbind_iterator","Entry.");
    if(iterator != (struct collection_iterator *)(NULL)) {
        destroy_collection(iterator->top);
        if(iterator->stack != (struct collection_item **)(NULL)) free(iterator->stack);
        free(iterator);
    }
    TRACE_FLOW_STRING("unbind_iterator","Exit");
}

/* Get items from the collection one by one following the tree */
int iterate_collection(struct collection_iterator *iterator, struct collection_item **item)
{
    int error;
    struct collection_item *current;
    struct collection_item *other;

    TRACE_FLOW_STRING("iterate_collection","Entry.");

    /* Check if we have storage for item */
    if(item == (struct collection_item **)(NULL)) {
        TRACE_ERROR_NUMBER("Invalid parameter.",EINVAL);
        return EINVAL;
    }

    while(1) {

        TRACE_INFO_NUMBER("Stack depth:",iterator->stack_depth);

        /* Are we done? */
        if(iterator->stack_depth == 0) {
            TRACE_FLOW_STRING("We are done.","");
            *item = (struct collection_item *)(NULL);
            return EOK;
        }

        /* Is current item available */
        current = *(iterator->stack + iterator->stack_depth - 1);

        /* We are not done so check if we have an item  */
        if(current != (struct collection_item *)(NULL)) {

            TRACE_INFO_STRING("Current item:",current->property);
            TRACE_INFO_NUMBER("Current item type:",current->type);

            /* Is this a collection reference */
            if(current->type == COL_TYPE_COLLECTIONREF) {
                /* We do follow references? */
                TRACE_INFO_STRING("Current item:","collection reference");
                if((iterator->flags & COL_TRAVERSE_IGNORE) == 0) {
                    /* We should not ignore - then move on */
                    TRACE_INFO_STRING("Collection references are not ignored","");
                    error = grow_stack(iterator,iterator->stack_depth + 1);
                    if(error) {
                        TRACE_ERROR_NUMBER("Error growing stack.",error);
                        return error;
                    }
                    /* Do we need to go deeper than one level ? */
                    if((iterator->flags & COL_TRAVERSE_ONELEVEL) == 0) {
                        TRACE_INFO_STRING("Need to go deeper","");
                        /* We need to go deeper... */
                        /* Do we need to show headers but not reference? */
                        if((iterator->flags & COL_TRAVERSE_ONLYSUB) != 0) {
                            TRACE_INFO_STRING("Instructed to show header not reference","");
                            other = *((struct collection_item **)(current->data));
                            *(iterator->stack + iterator->stack_depth) = other->next;
                            *item = other;
                        }
                        /* Do we need to show both? */
                        else if((iterator->flags & COL_TRAVERSE_SHOWSUB) != 0) {
                            TRACE_INFO_STRING("Instructed to show header and reference","");
                            *(iterator->stack + iterator->stack_depth) = *((struct collection_item **)(current->data));
                            *item = current;
                        }
                        /* We need to show reference only */
                        else {
                            TRACE_INFO_STRING("Instructed to show reference only","");
                            other = *((struct collection_item **)(current->data));
                            TRACE_INFO_STRING("Sub collection:",other->property);
                            TRACE_INFO_NUMBER("Sub collection type:",other->type);
                            *(iterator->stack + iterator->stack_depth) = other->next;
                            if(other->next != (struct collection_item *)(NULL)) {
                                TRACE_INFO_STRING("Will show this item next time:",(other->next)->property);
                                TRACE_INFO_NUMBER("Will show this item next time type:",(other->next)->type);
                            }
                            *item = current;
                        }

                        TRACE_INFO_STRING("We return item:",(*item)->property);
                        TRACE_INFO_NUMBER("We return item type:",(*item)->type);
                        TRACE_INFO_STRING("Moving to the next item on the previous item in stack","");
                        *(iterator->stack + iterator->stack_depth - 1) = current->next;
                        (iterator->stack_depth)++;

                    }
                    else {
                        TRACE_INFO_STRING("Instructed to parse just one level","");
                        /* On one level - just return current */
                        *item = current;
                        TRACE_INFO_STRING("Moving to the next item on one level","");
                        *(iterator->stack + iterator->stack_depth - 1) = current->next;
                    }
                    break;
                }
                else {
                    /* We need to ignore references so move to the next item */
                    TRACE_INFO_STRING("Stepping over the reference","");
                    *(iterator->stack + iterator->stack_depth - 1) = current->next;
                    continue;
                }
            }
            else {
                /* Got a normal item - return it and move to the next one */
                TRACE_INFO_STRING("Simple item","");
                *item = current;
                *(iterator->stack + iterator->stack_depth - 1) = current->next;
                break;
            }
        }
        else {
            /* Item is NULL */
            TRACE_INFO_STRING("Finished level","moving to upper level");
            iterator->stack_depth--;
            TRACE_INFO_NUMBER("Stack depth at the end:",iterator->stack_depth);
            if((iterator->flags & COL_TRAVERSE_END) != 0) {
                /* Return dummy entry to indicate the end of the collection */
                TRACE_INFO_STRING("Finished level","told to return END");
                *item = &dummy;
                break;
            }
            else continue; /* Move to next level */
        }
    }

    TRACE_FLOW_STRING("iterate_collection","Exit");
    return EOK;
}

/* Set collection class */
inline int set_collection_class(struct collection_item *item, unsigned class)
{
    struct collection_header *header;

    TRACE_FLOW_STRING("set_collection_class","Entry");

    if(item->type != COL_TYPE_COLLECTION) {
        TRACE_INFO_NUMBER("Not a collectin object. Type is",item->type);
        return EINVAL;
    }

    header = (struct collection_header *)(item->data);
    header->class = class;
    TRACE_FLOW_STRING("set_collection_class","Exit");
    return EOK;
}

/* Get collection class */
inline int get_collection_class(struct collection_item *item,
                                unsigned *class)
{
    struct collection_header *header;

    TRACE_FLOW_STRING("get_collection_class","Entry");

    if(item->type != COL_TYPE_COLLECTION) {
        TRACE_ERROR_NUMBER("Not a collection object. Type is",item->type);
        return EINVAL;
    }

    header = (struct collection_header *)(item->data);
    *class  = header->class;
    TRACE_FLOW_STRING("get_collection_class","Exit");
    return EOK;
}

/* Get collection count */
inline int get_collection_count(struct collection_item *item,
                                unsigned *count)
{
    struct collection_header *header;

    TRACE_FLOW_STRING("get_collection_count","Entry");

    if(item->type != COL_TYPE_COLLECTION) {
        TRACE_ERROR_NUMBER("Not a collectin object. Type is",item->type);
        return EINVAL;
    }

    header = (struct collection_header *)(item->data);
    *count  = header->count;
    TRACE_FLOW_STRING("get_collection_count","Exit");
    return EOK;

}

/* Convinience function to check if the collection is of the specific class */
/* In case of internal error assumes that collection is not of the right class */
inline int is_of_class(struct collection_item *item,unsigned class)
{
    int error = EOK;
    unsigned ret_class = 0;

    TRACE_FLOW_STRING("is_of_class invoked","");

    error = get_collection_class(item,&ret_class);
    if((error) || (ret_class != class)) return 0;
    else return 1;
}

/* Get propery */
inline char *get_item_property(struct collection_item *ci,int *property_len)
{
    if(property_len != NULL) *property_len = ci->property_len;
    return ci->property;
}

/* Get type */
inline int get_item_type(struct collection_item *ci)
{
    return ci->type;
}

/* Get length */
inline int get_item_length(struct collection_item *ci)
{
    return ci->length;
}

/* Get data */
void *get_item_data(struct collection_item *ci)
{
    return ci->data;
}


/* Set time stamp in the collection - FIXME move to another level */
int set_timestamp(struct collection_item *ci,struct collection_item **timestr_ref,struct collection_item **timeint_ref)
{
    time_t utctime;
    struct tm time_struct;
    char time_array[TIME_ARRAY_SIZE+1];
    int len;
    struct collection_item *timestr = (struct collection_item *)(NULL);
    struct collection_item *timeint = (struct collection_item *)(NULL);
    int error = EOK;

    TRACE_FLOW_STRING("set_timestamp","Entry point");

    utctime = time(NULL);
    localtime_r(&utctime,&time_struct);

    len = strftime(time_array, TIME_ARRAY_SIZE, DATE_FORMAT, &time_struct);
    if(len == 0) {
        TRACE_ERROR_STRING("add_time","CODING ERROR - INCREASE THE BUFFER");
        return EMSGSIZE;
    }

    TRACE_INFO_STRING("Timestamp:",time_array);

    /* Check if we have the timestamp item already */
    error = get_item(ci, TS_NAME, COL_TYPE_STRING,COL_TRAVERSE_IGNORE,&timestr);
    if(error) {
        TRACE_ERROR_NUMBER("search failed with error:",error);
        return error;
    }

    if(timestr != (struct collection_item *)(NULL)) {
        /* There is a timestamp */
        free(timestr->data);
        timestr->data = strdup(time_array);
        if(timestr->data == NULL) {
            TRACE_ERROR_NUMBER("failed to add timestamp property:",error);
            return ENOMEM;
        }
        timestr->length = len+1;
        *timestr_ref = timestr;
    }
    else {
        /* Add timestamp to the collection */
        error = add_str_property_with_ref(ci,NULL, TS_NAME,time_array,len+1,timestr_ref);
        if(error) {
            TRACE_ERROR_NUMBER("failed to add timestamp property:",error);
            return error;
        }
    }

    /* Check if we have the time item already */
    error = get_item(ci, T_NAME, COL_TYPE_INTEGER,COL_TRAVERSE_IGNORE,&timeint);
    if(error) {
        TRACE_ERROR_NUMBER("search failed with error:",error);
        return error;
    }

    if(timeint != (struct collection_item *)(NULL)) {
        /* There is a time property */
        *((int *)(timeint->data)) = utctime;
        *timeint_ref = timeint;
    }
    else {
        /* Add time to the collection */
        error = add_int_property_with_ref(ci,NULL, T_NAME,utctime,timeint_ref);
        if(error) {
            TRACE_ERROR_NUMBER("failed to add time property:",error);
            return error;
        }
    }

    TRACE_FLOW_STRING("set_timestamp","Exit point");
    return EOK;
}

