// SPDX-License-Identifier: MIT

#include "stdio.h"
#include <stdbool.h>
#include <stdlib.h>

struct list_head {
    struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list) {
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next) {
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head) { __list_add(new, head->prev, head); }

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define define_list(name, type)                                                                                              \
    struct name##_head {                                                                                                     \
        struct list_head _private;                                                                                           \
    };                                                                                                                       \
    static inline type *name##_head_first(struct name##_head *head) { return list_entry(head->_private.next, type, name); }  \
    static inline type *name##_next(const type *node) { return list_entry(node->name.next, type, name); }                    \
    static inline bool name##_is_last(struct name##_head *head, const type *node) { return &head->_private == &node->name; } \
    static inline void name##_init(struct name##_head *head) { INIT_LIST_HEAD(&head->_private); }                            \
    static inline void name##_add_tail(struct name##_head *head, type *new) { list_add_tail(&new->name, &head->_private); }
