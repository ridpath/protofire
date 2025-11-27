// modbus_module.c
#include "fuzzer_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <math.h>

// Safe type punning functions
static inline void write_float_as_bytes(uint8_t *dest, float value) {
    memcpy(dest, &value, sizeof(float));
}

static inline void write_double_as_bytes(uint8_t *dest, double value) {
    memcpy(dest, &value, sizeof(double));
}

static inline void write_uint32_as_bytes(uint8_t *dest, uint32_t value) {
    memcpy(dest, &value, sizeof(uint32_t));
}

static inline void write_uint64_as_bytes(uint8_t *dest, uint64_t value) {
    memcpy(dest, &value, sizeof(uint64_t));
}

static inline float read_uint32_as_float(const uint8_t *src) {
    uint32_t int_val;
    memcpy(&int_val, src, sizeof(uint32_t));
    return (float)int_val;
}

static inline double read_uint64_as_double(const uint8_t *src) {
    uint64_t int_val;
    memcpy(&int_val, src, sizeof(uint64_t));
    return (double)int_val;
}

#define MODBUS_TCP_HEADER_SIZE 6
#define MODBUS_PDU_HEADER_SIZE 1
#define MODBUS_READ_COILS_SIZE 12
#define MODBUS_READ_REGISTERS_SIZE 12
#define MODBUS_WRITE_SINGLE_COIL_SIZE 12
#define MODBUS_WRITE_SINGLE_REGISTER_SIZE 12
#define MODBUS_WRITE_MULTIPLE_COILS_SIZE 20
#define MODBUS_WRITE_MULTIPLE_REGISTERS_SIZE 20
#define MODBUS_DIAGNOSTIC_SIZE 16
#define MODBUS_MAX_PDU_LENGTH 253
#define MODBUS_MAX_REGISTERS 125
#define MODBUS_MAX_COILS 2000
#define MODBUS_MIN_LENGTH 7

typedef struct {
    uint8_t function_codes[64];
    uint8_t exception_codes[16];
    uint8_t diagnostic_codes[32];
    uint8_t memory_types[8];
    uint8_t data_patterns[32];
    uint8_t quality_codes[8];
    uint8_t error_masks[16];
    uint8_t timing_attacks[8];
} modbus_dictionary_t;

static const uint8_t FUNCTION_CODES[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x00, 0xFF, 0xFE, 0xFD, 0xFC,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F
};

static const uint8_t EXCEPTION_CODES[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0xFF
};

static const uint16_t DIAGNOSTIC_CODES[] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B,
    0x000C, 0x000D, 0x000E, 0x000F, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
    0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0xFFFF
};

static const uint8_t MEMORY_TYPES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF};
static const uint32_t DATA_PATTERNS[] = {
    0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x0000FFFF, 0xFFFF0000, 0x00FF00FF, 0xFF00FF00,
    0xAAAAAAAA, 0x55555555, 0x12345678, 0x87654321, 0xDEADBEEF, 0xBADC0FFE, 0xCAFEBABE, 0xABAD1DEA,
    0x00000001, 0x00010000, 0x01000000, 0x10000000, 0x00000100, 0x00010001, 0x01010101, 0x10101010,
    0x0F0F0F0F, 0xF0F0F0F0, 0x0FF00FF0, 0xF00FF00F, 0x0F0FF0F0, 0xF0F00F0F, 0x0FF0F0FF, 0xF00F0FF0
};

static void init_modbus_dictionary(modbus_dictionary_t *dict) {
    memcpy(dict->function_codes, FUNCTION_CODES, sizeof(FUNCTION_CODES));
    memcpy(dict->exception_codes, EXCEPTION_CODES, sizeof(EXCEPTION_CODES));
    
    for (int i = 0; i < 32; i++) {
        dict->diagnostic_codes[i] = DIAGNOSTIC_CODES[i] & 0xFF;
    }
    
    memcpy(dict->memory_types, MEMORY_TYPES, sizeof(MEMORY_TYPES));
    
    for (int i = 0; i < 32; i++) {
        dict->data_patterns[i] = DATA_PATTERNS[i] & 0xFF;
    }
    
    uint8_t qualities[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
    memcpy(dict->quality_codes, qualities, sizeof(qualities));
    
    uint8_t errors[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF};
    memcpy(dict->error_masks, errors, sizeof(errors));
    
    uint8_t timing[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
    memcpy(dict->timing_attacks, timing, sizeof(timing));
}

static void build_modbus_header(uint8_t *packet, uint16_t transaction_id, uint16_t protocol_id, uint16_t length, uint8_t unit_id) {
    packet[0] = (transaction_id >> 8) & 0xFF;
    packet[1] = transaction_id & 0xFF;
    packet[2] = (protocol_id >> 8) & 0xFF;
    packet[3] = protocol_id & 0xFF;
    packet[4] = (length >> 8) & 0xFF;
    packet[5] = length & 0xFF;
    packet[6] = unit_id;
}

static void build_modbus_pdu(uint8_t *packet, size_t *offset, uint8_t function_code, const uint8_t *data, size_t data_len) {
    packet[*offset] = function_code;
    (*offset)++;
    
    if (data && data_len > 0) {
        memcpy(packet + *offset, data, data_len);
        *offset += data_len;
    }
}

static void modbus_generate_read_coils(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 6, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x00, 0x00, 0x00, 0x64};
    build_modbus_pdu(packet, &offset, 0x01, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_read_registers(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 6, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x00, 0x00, 0x00, 0x64};
    build_modbus_pdu(packet, &offset, 0x03, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_write_single_coil(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 6, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x00, 0x00, 0xFF, 0x00};
    build_modbus_pdu(packet, &offset, 0x05, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_write_single_register(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 6, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x00, 0x00, 0x12, 0x34};
    build_modbus_pdu(packet, &offset, 0x06, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_write_multiple_coils(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 14, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x00, 0x00, 0x00, 0x64, 0x0D, 0xFF, 0x01};
    build_modbus_pdu(packet, &offset, 0x0F, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_write_multiple_registers(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 19, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x00, 0x00, 0x00, 0x64, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    build_modbus_pdu(packet, &offset, 0x10, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_diagnostic(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 6, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x00, 0x00, 0x00, 0x00};
    build_modbus_pdu(packet, &offset, 0x08, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_encapsulated_interface(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_modbus_header(packet, session ? session->transaction_id : 1, 0, 8, 1);
    offset += MODBUS_TCP_HEADER_SIZE;
    
    uint8_t pdu_data[] = {0x2B, 0x0D, 0x00, 0x01, 0x00, 0x00};
    build_modbus_pdu(packet, &offset, 0x2B, pdu_data, sizeof(pdu_data));
    
    *len = offset;
}

static void modbus_generate_packet(uint8_t *packet, size_t *len, int is_initial, int read_only, session_context_t *session) {
    if (is_initial) {
        modbus_generate_read_coils(packet, len, session);
    } else {
        if (read_only) {
            uint8_t read_type = rand() % 4;
            switch (read_type) {
                case 0: modbus_generate_read_coils(packet, len, session); break;
                case 1: modbus_generate_read_registers(packet, len, session); break;
                case 2: modbus_generate_diagnostic(packet, len, session); break;
                case 3: modbus_generate_encapsulated_interface(packet, len, session); break;
                default: modbus_generate_read_coils(packet, len, session); break;
            }
        } else {
            uint8_t write_type = rand() % 6;
            switch (write_type) {
                case 0: modbus_generate_write_single_coil(packet, len, session); break;
                case 1: modbus_generate_write_single_register(packet, len, session); break;
                case 2: modbus_generate_write_multiple_coils(packet, len, session); break;
                case 3: modbus_generate_write_multiple_registers(packet, len, session); break;
                case 4: modbus_generate_diagnostic(packet, len, session); break;
                case 5: modbus_generate_encapsulated_interface(packet, len, session); break;
                default: modbus_generate_write_single_coil(packet, len, session); break;
            }
        }
    }
    
    if (session) {
        session->transaction_id++;
    }
}

static void mutate_modbus_specific(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session) {
    (void)session;  // Mark unused parameter
    
    modbus_dictionary_t dict;
    init_modbus_dictionary(&dict);
    
    if (*len < MODBUS_TCP_HEADER_SIZE) return;
    
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    
    switch (strat) {
        case RANDOM:
            if (*len >= pdu_offset + 1) {
                packet[pdu_offset] = dict.function_codes[rand() % 64];
            }
            if (*len >= pdu_offset + 3) {
                packet[pdu_offset + 2] = dict.data_patterns[rand() % 32];
            }
            break;
            
        case BITFLIP:
            for (size_t i = pdu_offset; i < *len && i < pdu_offset + 16; i++) {
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= (1 << (rand() % 8));
                }
            }
            break;
            
        case OVERFLOW:
            if (*len >= 5) {
                packet[4] = 0xFF;
                packet[5] = 0xFF;
            }
            if (*len >= pdu_offset + 5) {
                packet[pdu_offset + 3] = 0xFF;
                packet[pdu_offset + 4] = 0xFF;
            }
            break;
            
        case DICTIONARY:
            if (*len >= pdu_offset + 1) {
                packet[pdu_offset] = dict.function_codes[rand() % 64];
            }
            if (*len >= pdu_offset + 2) {
                packet[pdu_offset + 1] = dict.memory_types[rand() % 8];
            }
            break;
            
        case FORMAT_STRING:
            if (*len >= pdu_offset + 10) {
                const char *modbus_formats[] = {
                    "FC%02X%s%s%s%s", "ADDR%04X%s%s%s%s", "CNT%04X%s%s%s%s",
                    "DATA%04X%s%s%s%s", "UNIT%02X%s%s%s%s", "TID%04X%s%s%s%s"
                };
                const char *inject = modbus_formats[rand() % 6];
                size_t inject_len = strlen(inject);
                if (pdu_offset + 5 + inject_len < *len) {
                    memcpy(packet + pdu_offset + 5, inject, inject_len);
                }
            }
            break;
            
        case TYPE_CONFUSION:
            if (*len >= pdu_offset + 8) {
                uint32_t int_val = 0xFFFFFFFF;
                float float_val;
                memcpy(&float_val, &int_val, sizeof(float_val));
                write_float_as_bytes(packet + pdu_offset + 4, float_val);
            }
            break;
            
        case TIME_BASED:
            if (*len >= pdu_offset + 12) {
                uint64_t future_time = 0xFFFFFFFFFFFFFFFFULL;
                write_uint64_as_bytes(packet + pdu_offset + 8, future_time);
            }
            break;
            
        case SEQUENCE_VIOLATION:
            if (*len >= 2) {
                packet[0] = 0xFF;
                packet[1] = 0xFF;
            }
            break;
            
        default:
            // Default mutation for unhandled strategies
            if (*len > 0) {
                size_t idx = rand() % *len;
                packet[idx] ^= 0x55;
            }
            break;
    }
}

static void inject_mbap_attack(uint8_t *packet, size_t *len) {
    if (*len < MODBUS_TCP_HEADER_SIZE) return;
    
    uint8_t attack_type = rand() % 8;
    
    switch (attack_type) {
        case 0:
            packet[0] = 0xFF;
            packet[1] = 0xFF;
            break;
        case 1:
            packet[2] = 0xFF;
            packet[3] = 0xFF;
            break;
        case 2:
            packet[4] = 0x00;
            packet[5] = 0x00;
            break;
        case 3:
            packet[4] = 0xFF;
            packet[5] = 0xFF;
            break;
        case 4:
            packet[6] = 0x00;
            break;
        case 5:
            packet[6] = 0xFF;
            break;
        case 6:
            packet[2] = 0x00;
            packet[3] = 0x01;
            break;
        case 7:
            packet[0] = 0x00;
            packet[1] = 0x00;
            break;
        default:
            break;
    }
}

static void inject_function_code_attack(uint8_t *packet, size_t *len) {
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    if (*len < pdu_offset + 1) return;
    
    uint8_t attack_type = rand() % 6;
    
    switch (attack_type) {
        case 0:
            packet[pdu_offset] = 0x00;
            break;
        case 1:
            packet[pdu_offset] = 0xFF;
            break;
        case 2:
            packet[pdu_offset] = 0x80;
            break;
        case 3:
            packet[pdu_offset] = 0x8F;
            break;
        case 4:
            packet[pdu_offset] = 0x2B;
            break;
        case 5:
            packet[pdu_offset] = 0x64;
            break;
        default:
            break;
    }
}

static void inject_address_attack(uint8_t *packet, size_t *len) {
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    if (*len < pdu_offset + 5) return;
    
    uint8_t attack_type = rand() % 6;
    
    switch (attack_type) {
        case 0:
            packet[pdu_offset + 1] = 0xFF;
            packet[pdu_offset + 2] = 0xFF;
            break;
        case 1:
            packet[pdu_offset + 1] = 0x00;
            packet[pdu_offset + 2] = 0x00;
            break;
        case 2:
            packet[pdu_offset + 1] = 0x7F;
            packet[pdu_offset + 2] = 0xFF;
            break;
        case 3:
            packet[pdu_offset + 1] = 0x80;
            packet[pdu_offset + 2] = 0x00;
            break;
        case 4:
            packet[pdu_offset + 1] = 0x12;
            packet[pdu_offset + 2] = 0x34;
            break;
        case 5:
            packet[pdu_offset + 1] = 0xAB;
            packet[pdu_offset + 2] = 0xCD;
            break;
        default:
            break;
    }
}

static void inject_quantity_attack(uint8_t *packet, size_t *len) {
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    if (*len < pdu_offset + 5) return;
    
    uint8_t attack_type = rand() % 8;
    
    switch (attack_type) {
        case 0:
            packet[pdu_offset + 3] = 0x00;
            packet[pdu_offset + 4] = 0x00;
            break;
        case 1:
            packet[pdu_offset + 3] = 0xFF;
            packet[pdu_offset + 4] = 0xFF;
            break;
        case 2:
            packet[pdu_offset + 3] = 0x00;
            packet[pdu_offset + 4] = 0x01;
            break;
        case 3:
            packet[pdu_offset + 3] = 0x00;
            packet[pdu_offset + 4] = 0x7D;
            break;
        case 4:
            packet[pdu_offset + 3] = 0x07;
            packet[pdu_offset + 4] = 0xD0;
            break;
        case 5:
            packet[pdu_offset + 3] = 0x80;
            packet[pdu_offset + 4] = 0x00;
            break;
        case 6:
            packet[pdu_offset + 3] = 0x7F;
            packet[pdu_offset + 4] = 0xFF;
            break;
        case 7:
            packet[pdu_offset + 3] = 0x12;
            packet[pdu_offset + 4] = 0x34;
            break;
        default:
            break;
    }
}

static void inject_data_attack(uint8_t *packet, size_t *len) {
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    if (*len < pdu_offset + 7) return;
    
    uint8_t attack_type = rand() % 6;
    
    switch (attack_type) {
        case 0:
            memset(packet + pdu_offset + 5, 0xFF, *len - pdu_offset - 5);
            break;
        case 1:
            memset(packet + pdu_offset + 5, 0x00, *len - pdu_offset - 5);
            break;
        case 2:
            for (size_t i = pdu_offset + 5; i < *len; i++) {
                packet[i] = 0xAA;
            }
            break;
        case 3:
            for (size_t i = pdu_offset + 5; i < *len; i++) {
                packet[i] = 0x55;
            }
            break;
        case 4:
            for (size_t i = pdu_offset + 5; i < *len; i++) {
                packet[i] = rand() % 256;
            }
            break;
        case 5:
            if (*len >= pdu_offset + 13) {
                uint64_t pattern = 0xDEADBEEFDEADBEEFULL;
                write_uint64_as_bytes(packet + pdu_offset + 5, pattern);
            }
            break;
        default:
            break;
    }
}

static void inject_diagnostic_attack(uint8_t *packet, size_t *len) {
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    if (*len < pdu_offset + 5) return;
    
    uint8_t attack_type = rand() % 5;
    
    switch (attack_type) {
        case 0:
            packet[pdu_offset + 1] = 0xFF;
            packet[pdu_offset + 2] = 0xFF;
            break;
        case 1:
            packet[pdu_offset + 1] = 0x00;
            packet[pdu_offset + 2] = 0x00;
            break;
        case 2:
            packet[pdu_offset + 1] = 0x12;
            packet[pdu_offset + 2] = 0x34;
            break;
        case 3:
            if (*len >= pdu_offset + 7) {
                packet[pdu_offset + 3] = 0xFF;
                packet[pdu_offset + 4] = 0xFF;
                packet[pdu_offset + 5] = 0xFF;
                packet[pdu_offset + 6] = 0xFF;
            }
            break;
        case 4:
            packet[pdu_offset] = 0x08;
            break;
        default:
            break;
    }
}

static void modbus_mutate_packet(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session) {
    (void)session;  // Mark unused parameter
    
    mutate_modbus_specific(packet, len, strat, rate, session);
    
    modbus_dictionary_t dict;
    init_modbus_dictionary(&dict);
    
    for (size_t i = 2; i < *len && i < BUF_SIZE; i++) {
        if ((float)rand() / RAND_MAX >= rate) continue;
        
        switch (strat) {
            case RANDOM:
                packet[i] = rand() % 256;
                break;
                
            case BITFLIP:
                packet[i] ^= (1 << (rand() % 8));
                break;
                
            case OVERFLOW:
                if ((i >= 4 && i <= 5) || (i >= 10 && i <= 11)) {
                    packet[i] = 0xFF;
                } else {
                    packet[i] = (packet[i] + 200) % 256;
                }
                break;
                
            case DICTIONARY:
                if (i == 7) packet[i] = dict.function_codes[rand() % 64];
                else if (i >= 8 && i < 12) packet[i] = dict.data_patterns[rand() % 32];
                else if (i == 6) packet[i] = dict.memory_types[rand() % 8];
                else packet[i] = dict.exception_codes[rand() % 16];
                break;
                
            case FORMAT_STRING:
                if (i < *len - 20) {
                    const char *modbus_strings[] = {
                        "FC%02X:ADDR%04X:CNT%04X", "UNIT%02X:TID%04X", "PROTO%04X:LEN%04X",
                        "DATA[%s%s%s%s]", "COIL%04X=%d", "REG%04X=%04X", "ERR%02X:%s%s%s%s"
                    };
                    const char *inject = modbus_strings[rand() % 7];
                    size_t inject_len = strlen(inject);
                    if (i + inject_len < *len) {
                        memcpy(&packet[i], inject, inject_len);
                        i += inject_len - 1;
                    }
                }
                break;
                
            case TYPE_CONFUSION:
                if (i < *len - 8) {
                    uint64_t large_int = 0xFFFFFFFFFFFFFFFFULL;
                    double large_float;
                    memcpy(&large_float, &large_int, sizeof(double));
                    write_double_as_bytes(&packet[i], large_float);
                    i += 7;
                }
                break;
                
            case TIME_BASED:
                if (i < *len - 8) {
                    uint64_t future_time = 0xFFFFFFFFFFFFFFFFULL - (time(NULL) % 1000000);
                    write_uint64_as_bytes(&packet[i], future_time);
                    i += 7;
                }
                break;
                
            case SEQUENCE_VIOLATION:
                if (i <= 1) {
                    packet[i] = (i == 0) ? 0xFE : 0xFF;
                }
                break;
                
            case PROTOCOL_FUZZING:
                packet[i] ^= 0xAA;
                break;
                
            case COMBINATORIAL:
                packet[i] = (dict.function_codes[rand() % 64] ^ 
                           dict.data_patterns[rand() % 32]) + 
                           dict.exception_codes[rand() % 16];
                break;
                
            default:
                // Default mutation for unhandled strategies
                packet[i] ^= 0x55;
                break;
        }
    }
    
    if (rand() % 3 == 0) {
        inject_mbap_attack(packet, len);
    }
    
    if (rand() % 3 == 0) {
        inject_function_code_attack(packet, len);
    }
    
    if (rand() % 3 == 0) {
        inject_address_attack(packet, len);
    }
    
    if (rand() % 3 == 0) {
        inject_quantity_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_data_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_diagnostic_attack(packet, len);
    }
    
    if (rand() % 5 == 0) {
        size_t new_len = rand() % BUF_SIZE;
        if (new_len > MODBUS_TCP_HEADER_SIZE) *len = new_len;
    }
    
    if (*len >= 5) {
        uint16_t pdu_length = *len - MODBUS_TCP_HEADER_SIZE;
        packet[4] = (pdu_length >> 8) & 0xFF;
        packet[5] = pdu_length & 0xFF;
    }
}

static int analyze_modbus_response(uint8_t *response, int len, session_context_t *session) {
    if (len <= 0) return -1;
    
    if (len < MODBUS_TCP_HEADER_SIZE) return 1;
    
    if (response[2] != 0x00 || response[3] != 0x00) return 2;
    
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    
    if ((size_t)len >= MODBUS_TCP_HEADER_SIZE) {
        uint16_t declared_length = (response[4] << 8) | response[5];
        if ((size_t)len != (size_t)declared_length + MODBUS_TCP_HEADER_SIZE) return 3;
    }
    
    if (len > MODBUS_MAX_PDU_LENGTH + MODBUS_TCP_HEADER_SIZE) return 4;
    
    if ((size_t)len >= pdu_offset + 1) {
        uint8_t function_code = response[pdu_offset];
        
        if (function_code >= 0x80) {
            if ((size_t)len >= pdu_offset + 2) {
                uint8_t exception_code = response[pdu_offset + 1];
                if (exception_code == 0x00 || exception_code > 0x0F) return 5;
            }
            return 6;
        }
        
        if (function_code == 0x00 || function_code > 0x6F) return 7;
        
        switch (function_code) {
            case 0x01:
            case 0x02:
                if ((size_t)len >= pdu_offset + 2) {
                    uint8_t byte_count = response[pdu_offset + 1];
                    if (byte_count == 0 || byte_count > 0xF7) return 8;
                    if ((size_t)len != pdu_offset + 2 + (size_t)byte_count) return 9;
                }
                break;
                
            case 0x03:
            case 0x04:
                if ((size_t)len >= pdu_offset + 2) {
                    uint8_t byte_count = response[pdu_offset + 1];
                    if (byte_count == 0 || byte_count > 0xFA) return 10;
                    if (byte_count % 2 != 0) return 11;
                    if ((size_t)len != pdu_offset + 2 + (size_t)byte_count) return 12;
                }
                break;
                
            case 0x05:
            case 0x06:
                if ((size_t)len != pdu_offset + 5) return 13;
                break;
                
            case 0x0F:
            case 0x10:
                if ((size_t)len != pdu_offset + 5) return 14;
                break;
                
            case 0x08:
                if ((size_t)len != pdu_offset + 5 && (size_t)len != pdu_offset + 7) return 15;
                break;
                
            case 0x2B:
                if ((size_t)len < pdu_offset + 3) return 16;
                break;
                
            default:
                // For other function codes, do basic length check
                if ((size_t)len < pdu_offset + 1) return 17;
                break;
        }
    }
    
    for (int i = 0; i < len - 4; i++) {
        if (response[i] == 0xBA && response[i+1] == 0xAD && 
            response[i+2] == 0xF0 && response[i+3] == 0x0D) {
            return 18;
        }
    }
    
    if (session) {
        session->last_response = time(NULL);
        if (len >= 2) {
            uint16_t transaction_id = (response[0] << 8) | response[1];
            session->transaction_id = transaction_id;
        }
    }
    
    return 0;
}

static protocol_ops_t modbus_ops = {
    .generate_packet = modbus_generate_packet,
    .mutate_packet = modbus_mutate_packet,
    .analyze_response = analyze_modbus_response
};

protocol_ops_t *get_protocol_ops(void) {
    return &modbus_ops;
}
