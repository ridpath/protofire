// dnp3_module.c
#include "fuzzer_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

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

#define DNP3_LINK_HEADER_SIZE 10
#define DNP3_TRANSPORT_HEADER_SIZE 1
#define DNP3_APPLICATION_HEADER_SIZE 2
#define DNP3_OBJECT_HEADER_SIZE 3
#define DNP3_READ_REQUEST_SIZE 17
#define DNP3_WRITE_REQUEST_SIZE 32
#define DNP3_SELECT_REQUEST_SIZE 28
#define DNP3_OPERATE_REQUEST_SIZE 35
#define DNP3_MAX_FRAGMENT_SIZE 292
#define DNP3_MAX_CHUNK_SIZE 16
#define DNP3_MIN_LENGTH 10

typedef struct {
    uint8_t function_codes[16];
    uint8_t internal_indications[8];
    uint8_t object_types[24];
    uint8_t qualifier_codes[12];
    uint8_t variation_codes[16];
    uint8_t control_codes[8];
    uint8_t time_synchronization[8];
    uint8_t event_classes[4];
} dnp3_dictionary_t;

static const uint8_t FUNCTION_CODES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t INTERNAL_INDICATIONS[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
static const uint16_t OBJECT_TYPES[] = {0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0xFFFF, 0xFFFE, 0x7FFF, 0x8000, 0x1234, 0x5678, 0x9ABC, 0xDEF0};
static const uint8_t QUALIFIER_CODES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};
static const uint8_t VARIATION_CODES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t CONTROL_CODES[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
static const uint8_t TIME_SYNCHRONIZATION[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
static const uint8_t EVENT_CLASSES[] = {0x01, 0x02, 0x03, 0x00};

static void init_dnp3_dictionary(dnp3_dictionary_t *dict) {
    memcpy(dict->function_codes, FUNCTION_CODES, sizeof(FUNCTION_CODES));
    memcpy(dict->internal_indications, INTERNAL_INDICATIONS, sizeof(INTERNAL_INDICATIONS));
    
    for (int i = 0; i < 24; i++) {
        dict->object_types[i] = OBJECT_TYPES[i] & 0xFF;
    }
    
    memcpy(dict->qualifier_codes, QUALIFIER_CODES, sizeof(QUALIFIER_CODES));
    memcpy(dict->variation_codes, VARIATION_CODES, sizeof(VARIATION_CODES));
    memcpy(dict->control_codes, CONTROL_CODES, sizeof(CONTROL_CODES));
    memcpy(dict->time_synchronization, TIME_SYNCHRONIZATION, sizeof(TIME_SYNCHRONIZATION));
    memcpy(dict->event_classes, EVENT_CLASSES, sizeof(EVENT_CLASSES));
}

static uint16_t calculate_dnp3_crc(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    const uint16_t polynomial = 0xA6BC;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return ~crc;
}

static void recalc_dnp3_crcs(uint8_t *packet, size_t *len) {
    if (*len < DNP3_LINK_HEADER_SIZE) return;
    
    uint16_t crc = calculate_dnp3_crc(packet, 8);
    packet[8] = crc & 0xFF;
    packet[9] = (crc >> 8) & 0xFF;
    
    size_t pos = DNP3_LINK_HEADER_SIZE;
    while (pos < *len) {
        size_t chunk_size = (*len - pos > DNP3_MAX_CHUNK_SIZE) ? DNP3_MAX_CHUNK_SIZE : (*len - pos);
        
        if (pos + chunk_size + 2 > BUF_SIZE) {
            chunk_size = BUF_SIZE - pos - 2;
        }
        
        if (chunk_size <= 0) break;
        
        crc = calculate_dnp3_crc(packet + pos, chunk_size);
        packet[pos + chunk_size] = crc & 0xFF;
        packet[pos + chunk_size + 1] = (crc >> 8) & 0xFF;
        
        pos += chunk_size + 2;
    }
    
    *len = pos;
}

static void build_dnp3_link_header(uint8_t *packet, uint16_t length, uint8_t control, uint16_t source, uint16_t destination) {
    packet[0] = 0x05;
    packet[1] = 0x64;
    packet[2] = (length >> 8) & 0xFF;
    packet[3] = length & 0xFF;
    packet[4] = control;
    packet[5] = (destination >> 8) & 0xFF;
    packet[6] = destination & 0xFF;
    packet[7] = (source >> 8) & 0xFF;
    packet[8] = source & 0xFF;
}

static void build_dnp3_transport_header(uint8_t *packet, uint8_t sequence, uint8_t fir, uint8_t fin) {
    packet[0] = (fir << 7) | (fin << 6) | (sequence & 0x3F);
}

static void build_dnp3_application_header(uint8_t *packet, uint8_t function, uint8_t internal_indications) {
    packet[0] = function;
    packet[1] = internal_indications;
}

static void build_dnp3_object_header(uint8_t *packet, uint16_t object_type, uint8_t qualifier, uint8_t variation, uint8_t range_specifier) {
    packet[0] = (object_type >> 8) & 0xFF;
    packet[1] = object_type & 0xFF;
    packet[2] = (qualifier << 6) | (variation & 0x3F);
    packet[3] = range_specifier;
}

static void build_dnp3_read_request(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_dnp3_link_header(packet, 7, 0xC4, session ? session->session_id : 1, session ? session->transaction_id : 1);
    offset += DNP3_LINK_HEADER_SIZE;
    
    build_dnp3_transport_header(packet + offset, session ? session->transaction_id & 0x3F : 1, 1, 1);
    offset += DNP3_TRANSPORT_HEADER_SIZE;
    
    build_dnp3_application_header(packet + offset, 0x01, 0x00);
    offset += DNP3_APPLICATION_HEADER_SIZE;
    
    build_dnp3_object_header(packet + offset, 0x0001, 0x00, 0x06, 0x00);
    offset += DNP3_OBJECT_HEADER_SIZE;
    
    *len = offset;
    recalc_dnp3_crcs(packet, len);
}

static void build_dnp3_write_request(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_dnp3_link_header(packet, 22, 0xC4, session ? session->session_id : 1, session ? session->transaction_id : 1);
    offset += DNP3_LINK_HEADER_SIZE;
    
    build_dnp3_transport_header(packet + offset, session ? session->transaction_id & 0x3F : 1, 1, 1);
    offset += DNP3_TRANSPORT_HEADER_SIZE;
    
    build_dnp3_application_header(packet + offset, 0x02, 0x00);
    offset += DNP3_APPLICATION_HEADER_SIZE;
    
    build_dnp3_object_header(packet + offset, 0x000A, 0x00, 0x01, 0x17);
    offset += DNP3_OBJECT_HEADER_SIZE;
    
    uint8_t analog_data[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(packet + offset, analog_data, sizeof(analog_data));
    offset += sizeof(analog_data);
    
    *len = offset;
    recalc_dnp3_crcs(packet, len);
}

static void build_dnp3_select_request(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_dnp3_link_header(packet, 18, 0xC4, session ? session->session_id : 1, session ? session->transaction_id : 1);
    offset += DNP3_LINK_HEADER_SIZE;
    
    build_dnp3_transport_header(packet + offset, session ? session->transaction_id & 0x3F : 1, 1, 1);
    offset += DNP3_TRANSPORT_HEADER_SIZE;
    
    build_dnp3_application_header(packet + offset, 0x03, 0x00);
    offset += DNP3_APPLICATION_HEADER_SIZE;
    
    build_dnp3_object_header(packet + offset, 0x000C, 0x00, 0x01, 0x07);
    offset += DNP3_OBJECT_HEADER_SIZE;
    
    uint8_t control_data[] = {0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(packet + offset, control_data, sizeof(control_data));
    offset += sizeof(control_data);
    
    *len = offset;
    recalc_dnp3_crcs(packet, len);
}

static void build_dnp3_operate_request(uint8_t *packet, size_t *len, session_context_t *session) {
    size_t offset = 0;
    
    build_dnp3_link_header(packet, 25, 0xC4, session ? session->session_id : 1, session ? session->transaction_id : 1);
    offset += DNP3_LINK_HEADER_SIZE;
    
    build_dnp3_transport_header(packet + offset, session ? session->transaction_id & 0x3F : 1, 1, 1);
    offset += DNP3_TRANSPORT_HEADER_SIZE;
    
    build_dnp3_application_header(packet + offset, 0x04, 0x00);
    offset += DNP3_APPLICATION_HEADER_SIZE;
    
    build_dnp3_object_header(packet + offset, 0x000C, 0x00, 0x01, 0x07);
    offset += DNP3_OBJECT_HEADER_SIZE;
    
    uint8_t operate_data[] = {0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(packet + offset, operate_data, sizeof(operate_data));
    offset += sizeof(operate_data);
    
    *len = offset;
    recalc_dnp3_crcs(packet, len);
}

static void dnp3_generate_packet(uint8_t *packet, size_t *len, int is_initial, int read_only, session_context_t *session) {
    if (is_initial) {
        build_dnp3_read_request(packet, len, session);
    } else {
        if (read_only) {
            build_dnp3_read_request(packet, len, session);
        } else {
            uint8_t request_type = rand() % 3;
            switch (request_type) {
                case 0:
                    build_dnp3_write_request(packet, len, session);
                    break;
                case 1:
                    build_dnp3_select_request(packet, len, session);
                    break;
                case 2:
                    build_dnp3_operate_request(packet, len, session);
                    break;
                default:
                    build_dnp3_read_request(packet, len, session);
                    break;
            }
        }
    }
    
    if (session) {
        session->transaction_id++;
    }
}

static void mutate_dnp3_specific(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session) {
    (void)session;  // Mark unused parameter
    
    dnp3_dictionary_t dict;
    init_dnp3_dictionary(&dict);
    
    if (*len < DNP3_LINK_HEADER_SIZE) return;
    
    size_t transport_offset = DNP3_LINK_HEADER_SIZE;
    size_t application_offset = transport_offset + DNP3_TRANSPORT_HEADER_SIZE;
    
    switch (strat) {
        case RANDOM:
            if (*len >= application_offset + 1) {
                packet[application_offset] = dict.function_codes[rand() % 16];
            }
            if (*len >= application_offset + DNP3_APPLICATION_HEADER_SIZE + 3) {
                packet[application_offset + DNP3_APPLICATION_HEADER_SIZE] = dict.object_types[rand() % 24];
                packet[application_offset + DNP3_APPLICATION_HEADER_SIZE + 2] = (dict.qualifier_codes[rand() % 12] << 6) | (dict.variation_codes[rand() % 16] & 0x3F);
            }
            break;
            
        case BITFLIP:
            for (size_t i = 4; i < *len && i < 16; i++) {
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= (1 << (rand() % 8));
                }
            }
            break;
            
        case OVERFLOW:
            if (*len >= 3) {
                packet[2] = 0xFF;
                packet[3] = 0xFF;
            }
            if (*len >= application_offset + DNP3_APPLICATION_HEADER_SIZE + 4) {
                packet[application_offset + DNP3_APPLICATION_HEADER_SIZE + 3] = 0xFF;
            }
            break;
            
        case DICTIONARY:
            if (*len >= 4) {
                packet[4] = dict.control_codes[rand() % 8];
            }
            if (*len >= application_offset + 1) {
                packet[application_offset] = dict.function_codes[rand() % 16];
            }
            break;
            
        case FORMAT_STRING:
            if (*len >= application_offset + DNP3_APPLICATION_HEADER_SIZE + 10) {
                const char *dnp3_formats[] = {
                    "OBJ%04X%s%s%s%s", "VAR%02X%s%s%s%s", "QUAL%02X%s%s%s%s",
                    "FUNC%02X%s%s%s%s", "CTRL%02X%s%s%s%s"
                };
                const char *inject = dnp3_formats[rand() % 5];
                size_t inject_len = strlen(inject);
                if (application_offset + DNP3_APPLICATION_HEADER_SIZE + 5 + inject_len < *len) {
                    memcpy(packet + application_offset + DNP3_APPLICATION_HEADER_SIZE + 5, inject, inject_len);
                }
            }
            break;
            
        case TYPE_CONFUSION:
            if (*len >= application_offset + DNP3_APPLICATION_HEADER_SIZE + 8) {
                uint32_t int_val = 0xFFFFFFFF;
                float float_val;
                memcpy(&float_val, &int_val, sizeof(float_val));
                write_float_as_bytes(packet + application_offset + DNP3_APPLICATION_HEADER_SIZE + 4, float_val);
            }
            break;
            
        case TIME_BASED:
            if (*len >= application_offset + DNP3_APPLICATION_HEADER_SIZE + 12) {
                uint64_t absolute_time = 0xFFFFFFFFFFFFFFFFULL;
                write_uint64_as_bytes(packet + application_offset + DNP3_APPLICATION_HEADER_SIZE + 8, absolute_time);
            }
            break;
            
        case SEQUENCE_VIOLATION:
            if (*len >= transport_offset) {
                packet[transport_offset] = 0xFF;
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

static void inject_link_layer_attack(uint8_t *packet, size_t *len) {
    if (*len < DNP3_LINK_HEADER_SIZE) return;
    
    uint8_t attack_type = rand() % 6;
    
    switch (attack_type) {
        case 0:
            packet[0] = 0x00;
            packet[1] = 0x00;
            break;
        case 1:
            packet[0] = 0xFF;
            packet[1] = 0xFF;
            break;
        case 2:
            packet[2] = 0xFF;
            packet[3] = 0xFF;
            break;
        case 3:
            packet[4] = 0x00;
            break;
        case 4:
            packet[4] = 0xFF;
            break;
        case 5:
            packet[5] = 0xFF;
            packet[6] = 0xFF;
            packet[7] = 0xFF;
            packet[8] = 0xFF;
            break;
        default:
            break;
    }
}

static void inject_transport_layer_attack(uint8_t *packet, size_t *len) {
    size_t transport_offset = DNP3_LINK_HEADER_SIZE;
    if (*len < transport_offset + DNP3_TRANSPORT_HEADER_SIZE) return;
    
    uint8_t attack_type = rand() % 4;
    
    switch (attack_type) {
        case 0:
            packet[transport_offset] = 0x00;
            break;
        case 1:
            packet[transport_offset] = 0xFF;
            break;
        case 2:
            packet[transport_offset] = 0x80;
            break;
        case 3:
            packet[transport_offset] = 0xC0;
            break;
        default:
            break;
    }
}

static void inject_application_layer_attack(uint8_t *packet, size_t *len) {
    size_t application_offset = DNP3_LINK_HEADER_SIZE + DNP3_TRANSPORT_HEADER_SIZE;
    if (*len < application_offset + DNP3_APPLICATION_HEADER_SIZE) return;
    
    uint8_t attack_type = rand() % 5;
    
    switch (attack_type) {
        case 0:
            packet[application_offset] = 0x00;
            break;
        case 1:
            packet[application_offset] = 0xFF;
            break;
        case 2:
            packet[application_offset + 1] = 0xFF;
            break;
        case 3:
            packet[application_offset] = 0x80;
            break;
        case 4:
            packet[application_offset] = 0xFE;
            break;
        default:
            break;
    }
}

static void inject_object_header_attack(uint8_t *packet, size_t *len) {
    size_t object_offset = DNP3_LINK_HEADER_SIZE + DNP3_TRANSPORT_HEADER_SIZE + DNP3_APPLICATION_HEADER_SIZE;
    if (*len < object_offset + DNP3_OBJECT_HEADER_SIZE) return;
    
    uint8_t attack_type = rand() % 6;
    
    switch (attack_type) {
        case 0:
            packet[object_offset] = 0xFF;
            packet[object_offset + 1] = 0xFF;
            break;
        case 1:
            packet[object_offset] = 0x00;
            packet[object_offset + 1] = 0x00;
            break;
        case 2:
            packet[object_offset + 2] = 0xFF;
            break;
        case 3:
            packet[object_offset + 2] = 0x00;
            break;
        case 4:
            packet[object_offset + 3] = 0xFF;
            break;
        case 5:
            packet[object_offset + 3] = 0x00;
            break;
        default:
            break;
    }
}

static void inject_crc_attack(uint8_t *packet, size_t *len) {
    if (*len < DNP3_LINK_HEADER_SIZE) return;
    
    uint8_t attack_type = rand() % 4;
    
    switch (attack_type) {
        case 0:
            packet[8] = 0x00;
            packet[9] = 0x00;
            break;
        case 1:
            packet[8] = 0xFF;
            packet[9] = 0xFF;
            break;
        case 2:
            if (*len > 12) {
                packet[*len - 2] = 0x00;
                packet[*len - 1] = 0x00;
            }
            break;
        case 3:
            if (*len > 12) {
                packet[*len - 2] = 0xFF;
                packet[*len - 1] = 0xFF;
            }
            break;
        default:
            break;
    }
}

static void dnp3_mutate_packet(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session) {
    (void)session;  // Mark unused parameter
    
    mutate_dnp3_specific(packet, len, strat, rate, session);
    
    dnp3_dictionary_t dict;
    init_dnp3_dictionary(&dict);
    
    for (size_t i = 5; i < *len && i < BUF_SIZE; i++) {
        if ((float)rand() / RAND_MAX >= rate) continue;
        
        switch (strat) {
            case RANDOM:
                packet[i] = rand() % 256;
                break;
                
            case BITFLIP:
                packet[i] ^= (1 << (rand() % 8));
                break;
                
            case OVERFLOW:
                if (i >= 2 && i <= 3) {
                    packet[i] = 0xFF;
                } else if (i >= 10 && i <= 15) {
                    packet[i] = 0xFF;
                } else {
                    packet[i] = (packet[i] + 200) % 256;
                }
                break;
                
            case DICTIONARY:
                if (i == 4) packet[i] = dict.control_codes[rand() % 8];
                else if (i == 10) packet[i] = dict.function_codes[rand() % 16];
                else if (i == 11) packet[i] = dict.internal_indications[rand() % 8];
                else if (i >= 12 && i < 16) packet[i] = dict.object_types[rand() % 24];
                else if (i == 14) packet[i] = (dict.qualifier_codes[rand() % 12] << 6) | (dict.variation_codes[rand() % 16] & 0x3F);
                else packet[i] = dict.time_synchronization[rand() % 8];
                break;
                
            case FORMAT_STRING:
                if (i < *len - 12) {
                    const char *dnp3_strings[] = {
                        "OBJ%04X:%s%s%s%s", "VAR%02X:%s%s%s%s", "QUAL%02X:%s%s%s%s",
                        "FUNC%02X:%s%s%s%s", "CTRL%02X:%s%s%s%s", "TIME%lu%s%s%s%s"
                    };
                    const char *inject = dnp3_strings[rand() % 6];
                    size_t inject_len = strlen(inject);
                    if (i + inject_len < *len) {
                        memcpy(&packet[i], inject, inject_len);
                        i += inject_len - 1;
                    }
                }
                break;
                
            case TYPE_CONFUSION:
                if (i < *len - 8) {
                    uint64_t large_int = 0xDEADBEEFDEADBEEFULL;
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
                if (i == 10) {
                    packet[i] = 0xFF;
                }
                break;
                
            case PROTOCOL_FUZZING:
                packet[i] ^= 0xAA;
                break;
                
            case COMBINATORIAL:
                packet[i] = (dict.function_codes[rand() % 16] ^ 
                           dict.object_types[rand() % 24]) + 
                           dict.qualifier_codes[rand() % 12];
                break;
                
            default:
                // Default mutation for unhandled strategies
                packet[i] ^= 0x55;
                break;
        }
    }
    
    if (rand() % 3 == 0) {
        inject_link_layer_attack(packet, len);
    }
    
    if (rand() % 3 == 0) {
        inject_transport_layer_attack(packet, len);
    }
    
    if (rand() % 3 == 0) {
        inject_application_layer_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_object_header_attack(packet, len);
    }
    
    if (rand() % 4 == 0) {
        inject_crc_attack(packet, len);
    }
    
    if (rand() % 5 == 0) {
        size_t new_len = rand() % BUF_SIZE;
        if (new_len > DNP3_LINK_HEADER_SIZE) *len = new_len;
    }
    
    recalc_dnp3_crcs(packet, len);
}

static int analyze_dnp3_response(uint8_t *response, int len, session_context_t *session) {
    if (len <= 0) return -1;
    
    if (len < DNP3_LINK_HEADER_SIZE) return 1;
    
    if (response[0] != 0x05 || response[1] != 0x64) return 2;
    
    if ((size_t)len >= DNP3_LINK_HEADER_SIZE) {
        uint16_t declared_length = (response[2] << 8) | response[3];
        if ((size_t)len < (size_t)declared_length + 2) return 3;
    }
    
    if (len > DNP3_MAX_FRAGMENT_SIZE) return 4;
    
    for (int i = 0; i < len - 1; i += 2) {
        if (i + 10 < len) {
            uint16_t calculated_crc = calculate_dnp3_crc(response + i, 8);
            uint16_t received_crc = (response[i + 9] << 8) | response[i + 8];
            if (calculated_crc != received_crc) return 5;
        }
    }
    
    size_t application_offset = DNP3_LINK_HEADER_SIZE + DNP3_TRANSPORT_HEADER_SIZE;
    if ((size_t)len >= application_offset + DNP3_APPLICATION_HEADER_SIZE) {
        uint8_t function_code = response[application_offset];
        if (function_code >= 0x80) return 6;
        
        uint8_t internal_indications = response[application_offset + 1];
        if (internal_indications != 0x00) return 7;
    }
    
    if ((size_t)len >= application_offset + DNP3_APPLICATION_HEADER_SIZE + DNP3_OBJECT_HEADER_SIZE) {
        uint16_t object_type = (response[application_offset + DNP3_APPLICATION_HEADER_SIZE] << 8) | 
                              response[application_offset + DNP3_APPLICATION_HEADER_SIZE + 1];
        if (object_type == 0x0000 || object_type >= 0xFF00) return 8;
    }
    
    for (int i = 0; i < len - 4; i++) {
        if (response[i] == 0xBA && response[i+1] == 0xAD && 
            response[i+2] == 0xF0 && response[i+3] == 0x0D) {
            return 9;
        }
    }
    
    if (session) {
        session->last_response = time(NULL);
        if (len >= 8) {
            uint16_t source_address = (response[7] << 8) | response[8];
            session->transaction_id = source_address;
        }
    }
    
    return 0;
}

static protocol_ops_t dnp3_ops = {
    .generate_packet = dnp3_generate_packet,
    .mutate_packet = dnp3_mutate_packet,
    .analyze_response = analyze_dnp3_response
};

protocol_ops_t *get_protocol_ops(void) {
    return &dnp3_ops;
}
