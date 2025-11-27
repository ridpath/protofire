#ifndef GRAMMAR_FIELDMAP_H
#define GRAMMAR_FIELDMAP_H

#include <stddef.h>
#include <stdint.h>

#define BUF_SIZE 4096

typedef enum {
    FIELD_CONST,
    FIELD_FUNC_CODE,
    FIELD_ADDR,
    FIELD_LEN,
    FIELD_PAYLOAD,
    FIELD_CRC,
    FIELD_UNKNOWN
} field_type_t;

typedef struct {
    size_t offset;
    size_t length;
    field_type_t type;
} field_descriptor_t;

typedef struct {
    uint8_t template_data[BUF_SIZE];
    size_t template_len;
    field_descriptor_t fields[16];
    int field_count;
} grammar_template_t;

#endif
