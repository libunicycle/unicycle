// SPDX-License-Identifier: MIT

// The code is port of LLVM's code https://llvm.org/viewvc/llvm-project/compiler-rt/trunk/lib/ubsan/ubsan_handlers.cc

#include "compiler.h"
#include "shout.h"
#include <stdint.h>
#include <stdio.h>

#define VALUE_LENGTH 40

enum { type_kind_int = 0, type_kind_float = 1, type_unknown = 0xffff };

const char *type_check_kinds[] = {"load of",
                                  "store to",
                                  "reference binding to",
                                  "member access within",
                                  "member call on",
                                  "constructor call on",
                                  "downcast of",
                                  "downcast of",
                                  "upcast of",
                                  "cast to virtual base of",
                                  "_Nonnull binding to",
                                  "dynamic operation on"};

struct type_descriptor {
    uint16_t type_kind;
    uint16_t type_info;
    char type_name[];
};

struct source_location {
    const char *file_name;
    uint32_t line;
    uint32_t column;
};

struct type_mismatch_data {
    struct source_location location;
    struct type_descriptor *type;
    unsigned long alignment;
    unsigned char type_check_kind;
};

struct type_mismatch_data_v1 {
    struct source_location location;
    struct type_descriptor *type;
    unsigned char log_alignment;
    unsigned char type_check_kind;
};

struct unreachable_data {
    struct source_location location;
};

struct out_of_bounds_data {
    struct source_location location;
    struct type_descriptor *array_type;
    struct type_descriptor *index_type;
};

struct overflow_data {
    struct source_location location;
    struct type_descriptor *type;
};

struct invalid_value_data {
    struct source_location location;
    struct type_descriptor *type;
};

struct shift_out_of_bounds_data {
    struct source_location location;
    struct type_descriptor *lhs_type;
    struct type_descriptor *rhs_type;
};

struct pointer_overflow_data {
    struct source_location location;
};

#define TYPE_INFO_SIGNED BIT(0)

static bool type_is_int(struct type_descriptor *type) { return type->type_kind == type_kind_int; }
static size_t type_bit_width(struct type_descriptor *type) { return 1 << (type->type_info >> 1); }
static bool type_is_signed(struct type_descriptor *type) { return type->type_info & TYPE_INFO_SIGNED; }
static bool is_inline_int(struct type_descriptor *type) { return type_bit_width(type) <= sizeof(void *) * 8; }

static int64_t get_signed_val(struct type_descriptor *type, void *val) {
    if (is_inline_int(type)) {
        // extend sign bit
        size_t extra_bits = sizeof(void *) * 8 - type_bit_width(type);
        return (int64_t)val << extra_bits >> extra_bits;
    }

    return *(int64_t *)val;
}

static bool val_is_negative(struct type_descriptor *type, void *val) { return type_is_signed(type) && get_signed_val(type, val) < 0; }

static uint64_t get_unsigned_val(struct type_descriptor *type, void *val) {
    if (is_inline_int(type))
        return (uint64_t)val;

    return *(uint64_t *)val;
}

static void val_to_string(char *str, size_t size, struct type_descriptor *type, void *value) {
    if (type_is_int(type)) {
        if (type_bit_width(type) == 128)
            PANIC("UBSAN does not support 128-bit values yet");
        else if (type_is_signed(type))
            snprintf(str, size, "%ld%c", get_signed_val(type, value), '\0');
        else
            snprintf(str, size, "%lu%c", get_unsigned_val(type, value), '\0');
    } else {
        PANIC("Value is not integer type");
    }
}

static void print_source_location(struct source_location *loc) { printf("  %s:%d:%d\n", loc->file_name, loc->line, loc->column); }

__attribute__((externally_visible)) void __ubsan_handle_builtin_unreachable(struct unreachable_data *data) {
    printf("!!!!!!!! __ubsan_handle_builtin_unreachable ");
    print_source_location(&data->location);
}

static void handle_type_mismatch_common(struct source_location *location, struct type_descriptor *type, size_t alignment,
                                        unsigned char type_check_kind, void *ptr) {
    printf("!!!!!!!! __ubsan_handle_type_mismatch ");
    print_source_location(location);

    if (!ptr)
        printf("%s null pointer of type %s\n", type_check_kinds[type_check_kind], type->type_name);
    else if (alignment && !IS_ROUNDED((uintptr_t)ptr, alignment))
        printf("%s misaligned address %p for type %s which requires %ld byte alignment\n", type_check_kinds[type_check_kind], ptr,
               type->type_name, alignment);
    else
        printf("%s address %p with insufficient space for an object of type %s\n", type_check_kinds[type_check_kind], ptr, type->type_name);
}

__attribute__((externally_visible)) void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr) {
    handle_type_mismatch_common(&data->location, data->type, data->alignment, data->type_check_kind, ptr);
}

__attribute__((externally_visible)) void __ubsan_handle_type_mismatch_v1(struct type_mismatch_data_v1 *data, void *ptr) {
    handle_type_mismatch_common(&data->location, data->type, 1UL << data->log_alignment, data->type_check_kind, ptr);
}

__attribute__((externally_visible)) void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data, void *index) {
    printf("!!!!!!!! __ubsan_handle_out_of_bounds");
    print_source_location(&data->location);

    char index_str[VALUE_LENGTH];
    PANIC_IF(!type_is_int(data->index_type));
    val_to_string(index_str, sizeof(index_str), data->index_type, index);
    printf("index %s is out of range for type %s\n", index_str, data->array_type->type_name);
}

__attribute__((externally_visible)) void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data, void *lhs, void *rhs) {
    printf("!!!!!!!! __ubsan_handle_shift_out_of_bounds ");
    print_source_location(&data->location);

    struct type_descriptor *rhs_type = data->rhs_type;
    struct type_descriptor *lhs_type = data->lhs_type;
    char rhs_str[VALUE_LENGTH];
    char lhs_str[VALUE_LENGTH];

    PANIC_IF(!type_is_int(rhs_type));
    PANIC_IF(!type_is_int(lhs_type));

    val_to_string(rhs_str, sizeof(rhs_str), rhs_type, rhs);
    val_to_string(lhs_str, sizeof(lhs_str), lhs_type, lhs);

    if (val_is_negative(rhs_type, rhs))
        printf("shift exponent %s is negative\n", rhs_str);
    else if (get_unsigned_val(rhs_type, rhs) >= type_bit_width(lhs_type))
        printf("shift exponent %s is too large for %lu-bit type %s\n", rhs_str, type_bit_width(lhs_type), lhs_type->type_name);
    else if (val_is_negative(lhs_type, lhs))
        printf("left shift of negative value %s\n", lhs_str);
    else
        printf("left shift of %s by %s places cannot be represented in type %s\n", lhs_str, rhs_str, lhs_type->type_name);
}

static void handle_overflow(struct overflow_data *data, void *lhs, void *rhs, char op) {
    char lhs_val_str[VALUE_LENGTH];
    char rhs_val_str[VALUE_LENGTH];

    struct type_descriptor *type = data->type;
    PANIC_IF(!type_is_int(type));

    val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
    val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
    printf("%s integer overflow: %s %c %s cannot be represented in type %s\n", type_is_signed(type) ? "signed" : "unsigned", lhs_val_str,
           op, rhs_val_str, type->type_name);
}

__attribute__((externally_visible)) void __ubsan_handle_sub_overflow(struct overflow_data *data, void *lhs, void *rhs) {
    printf("!!!!!!!! __ubsan_handle_sub_overflow ");
    print_source_location(&data->location);
    handle_overflow(data, lhs, rhs, '-');
}

__attribute__((externally_visible)) void __ubsan_handle_add_overflow(struct overflow_data *data, void *lhs, void *rhs) {
    printf("!!!!!!!! __ubsan_handle_add_overflow ");
    print_source_location(&data->location);
    handle_overflow(data, lhs, rhs, '+');
}

__attribute__((externally_visible)) void __ubsan_handle_mul_overflow(struct overflow_data *data, void *lhs, void *rhs) {
    printf("!!!!!!!! __ubsan_handle_mul_overflow ");
    print_source_location(&data->location);
    handle_overflow(data, lhs, rhs, '*');
}

__attribute__((externally_visible)) void __ubsan_handle_divrem_overflow(struct overflow_data *data, void *lhs, void *rhs) {
    printf("!!!!!!!! __ubsan_handle_divrem_overflow ");
    print_source_location(&data->location);

    char lhs_val_str[VALUE_LENGTH];
    val_to_string(lhs_val_str, sizeof(lhs_val_str), data->type, lhs);

    if (type_is_signed(data->type) && get_signed_val(data->type, rhs) == -1)
        printf("division of %s by -1 cannot be represented in type %s\n", lhs_val_str, data->type->type_name);
    else
        printf("division by zero\n");
}

__attribute__((externally_visible)) void __ubsan_handle_negate_overflow(struct overflow_data *data, void *old_val) {
    printf("!!!!!!!! __ubsan_handle_negate_overflow ");
    print_source_location(&data->location);

    char old_val_str[VALUE_LENGTH];
    val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);

    printf("negation of %s cannot be represented in type %s:\n", old_val_str, data->type->type_name);
}

__attribute__((externally_visible)) void __ubsan_handle_load_invalid_value(struct invalid_value_data *data, void *val) {
    printf("!!!!!!!! __ubsan_handle_load_invalid_value ");
    print_source_location(&data->location);

    char val_str[VALUE_LENGTH];
    val_to_string(val_str, sizeof(val_str), data->type, val);

    printf("load of value %s is not a valid value for type %s\n", val_str, data->type->type_name);
}

__attribute__((externally_visible)) void __ubsan_handle_pointer_overflow(struct pointer_overflow_data *data, unsigned long base,
                                                                         unsigned long result) {

    printf("!!!!!!!! __ubsan_handle_pointer_overflow ");
    print_source_location(&data->location);

    if (((long)base >= 0) == ((long)result >= 0))
        printf("%s of unsigned offset to %p overflowed to %p", base > result ? "addition" : "subtraction", (void *)base, (void *)result);
    else
        printf("pointer index expression with base %p overflowed to %p", (void *)base, (void *)result);
}
