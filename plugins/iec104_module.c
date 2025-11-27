// iec104_module.c
#include "fuzzer_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#define IEC104_APCI_LENGTH 6
#define IEC104_ASDU_MIN_LENGTH 6
#define IEC104_MAX_ASDU_LENGTH 249
#define IEC104_TYPE_ID_M_SP_NA_1 1
#define IEC104_TYPE_ID_M_ME_NC_1 13
#define IEC104_TYPE_ID_C_IC_NA_1 100
#define IEC104_CAUSE_SIZE 2
#define IEC104_IOA_SIZE 3

// Safe type punning functions
static inline void write_float_as_bytes(uint8_t *dest, float value) {
    memcpy(dest, &value, sizeof(float));
}

static inline void write_uint32_as_bytes(uint8_t *dest, uint32_t value) {
    memcpy(dest, &value, sizeof(uint32_t));
}

static inline void write_uint64_as_bytes(uint8_t *dest, uint64_t value) {
    memcpy(dest, &value, sizeof(uint64_t));
}

static inline float bytes_to_float(const uint8_t *src) {
    float value;
    memcpy(&value, src, sizeof(float));
    return value;
}

typedef struct {
    uint8_t invalid_type_ids[16];
    uint8_t cause_of_transmission[8];
    uint8_t common_addresses[8];
    uint8_t information_object_addresses[16];
    uint8_t quality_descriptors[8];
    uint8_t time_patterns[24];
} iec104_dictionary_t;

static const uint8_t INVALID_TYPE_IDS[] = {0x00, 0xFF, 0xFE, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B};
static const uint8_t CAUSE_VALUES[] = {0x00, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const uint16_t COMMON_ADDRESSES[] = {0x0000, 0x0001, 0xFFFF, 0xFFFE, 0x7FFF, 0x8000, 0x1234, 0x5678};
static const uint32_t IOA_VALUES[] = {0x000000, 0x000001, 0xFFFFFF, 0xFFFFFE, 0x7FFFFF, 0x800000, 0x123456, 0x789ABC};

static void init_iec104_dictionary(iec104_dictionary_t *dict) {
    memcpy(dict->invalid_type_ids, INVALID_TYPE_IDS, sizeof(INVALID_TYPE_IDS));
    memcpy(dict->cause_of_transmission, CAUSE_VALUES, sizeof(CAUSE_VALUES));
    
    for (int i = 0; i < 8; i++) {
        dict->common_addresses[i] = COMMON_ADDRESSES[i] & 0xFF;
    }
    
    for (int i = 0; i < 8; i++) {
        dict->information_object_addresses[i*2] = (IOA_VALUES[i] >> 8) & 0xFF;
        dict->information_object_addresses[i*2+1] = IOA_VALUES[i] & 0xFF;
    }
    
    uint8_t qualities[] = {0x00, 0x01, 0x10, 0x20, 0x40, 0x80, 0xC0, 0xFF};
    memcpy(dict->quality_descriptors, qualities, sizeof(qualities));
    
    uint8_t times[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F
    };
    memcpy(dict->time_patterns, times, sizeof(times));
}

static uint8_t calculate_iec104_checksum(const uint8_t *data, size_t len) {
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (sum + data[i]) & 0xFF;
    }
    return sum;
}

static void recalc_iec104_length_and_checksum(uint8_t *packet, size_t *len) {
    if (*len < IEC104_APCI_LENGTH) return;
    
    size_t asdu_length = *len - IEC104_APCI_LENGTH;
    if (asdu_length > IEC104_MAX_ASDU_LENGTH) {
        asdu_length = IEC104_MAX_ASDU_LENGTH;
        *len = IEC104_APCI_LENGTH + asdu_length;
    }
    
    packet[1] = asdu_length + 2;
    
    if (*len > IEC104_APCI_LENGTH) {
        uint8_t checksum = calculate_iec104_checksum(packet + 2, *len - 3);
        packet[*len - 1] = checksum;
    }
}

static uint16_t generate_sequence_number(session_context_t *session, int is_send) {
    if (!session) return 1;
    
    static uint16_t sequence = 1;
    if (is_send) {
        session->transaction_id = sequence;
        return sequence++;
    }
    return session->transaction_id;
}

static void build_iec104_apci(uint8_t *packet, uint8_t type, uint16_t send_seq, uint16_t receive_seq, size_t *len) {
    packet[0] = 0x68;
    
    switch (type) {
        case 'I':
            packet[2] = (send_seq << 1) & 0xFF;
            packet[3] = (send_seq >> 7) & 0xFF;
            packet[4] = (receive_seq << 1) & 0xFF;
            packet[5] = (receive_seq >> 7) & 0xFF;
            break;
        case 'S':
            packet[2] = 0x01;
            packet[3] = 0x00;
            packet[4] = (receive_seq << 1) & 0xFF;
            packet[5] = (receive_seq >> 7) & 0xFF;
            break;
        case 'U':
            packet[2] = 0x07;
            packet[3] = 0x00;
            packet[4] = 0x00;
            packet[5] = 0x00;
            break;
        default:
            packet[2] = (send_seq << 1) & 0xFF;
            packet[3] = (send_seq >> 7) & 0xFF;
            packet[4] = (receive_seq << 1) & 0xFF;
            packet[5] = (receive_seq >> 7) & 0xFF;
            break;
    }
    
    *len = IEC104_APCI_LENGTH;
}

static void build_iec104_asdu(uint8_t *packet, size_t *offset, uint8_t type_id, uint8_t sq, uint8_t cause, uint16_t common_addr) {
    packet[*offset] = type_id;
    packet[*offset + 1] = (sq & 0x80) | (1 & 0x7F);
    packet[*offset + 2] = cause;
    packet[*offset + 3] = common_addr & 0xFF;
    packet[*offset + 4] = (common_addr >> 8) & 0xFF;
    *offset += 5;
}

static void add_single_point_information(uint8_t *packet, size_t *offset, uint32_t ioa, uint8_t value, uint8_t quality) {
    packet[*offset] = ioa & 0xFF;
    packet[*offset + 1] = (ioa >> 8) & 0xFF;
    packet[*offset + 2] = (ioa >> 16) & 0xFF;
    packet[*offset + 3] = value;
    packet[*offset + 4] = quality;
    *offset += 5;
}

static void add_measurement_value(uint8_t *packet, size_t *offset, uint32_t ioa, float value, uint8_t quality) {
    packet[*offset] = ioa & 0xFF;
    packet[*offset + 1] = (ioa >> 8) & 0xFF;
    packet[*offset + 2] = (ioa >> 16) & 0xFF;
    
    // FIXED: Use safe type punning instead of pointer casting
    write_float_as_bytes(packet + *offset + 3, value);
    
    packet[*offset + 7] = quality;
    *offset += 8;
}

static void iec104_generate_packet(uint8_t *packet, size_t *len, int is_initial, int read_only, session_context_t *session) {
    uint8_t frame_type = 'I';
    uint16_t send_seq = generate_sequence_number(session, 1);
    uint16_t recv_seq = is_initial ? 0 : (send_seq > 10 ? send_seq - 10 : 0);
    
    if (is_initial) {
        frame_type = 'U';
    } else if (rand() % 10 == 0) {
        frame_type = (rand() % 2) ? 'S' : 'U';
    }
    
    build_iec104_apci(packet, frame_type, send_seq, recv_seq, len);
    
    if (frame_type == 'I') {
        size_t offset = IEC104_APCI_LENGTH;
        uint8_t type_id = read_only ? IEC104_TYPE_ID_M_SP_NA_1 : 
                         (rand() % 2 ? IEC104_TYPE_ID_M_SP_NA_1 : IEC104_TYPE_ID_M_ME_NC_1);
        
        build_iec104_asdu(packet, &offset, type_id, 0, 3, 1);
        
        if (type_id == IEC104_TYPE_ID_M_SP_NA_1) {
            add_single_point_information(packet, &offset, 0x000001, rand() % 2, 0x00);
        } else {
            float value = (float)(rand() % 1000) / 10.0f;
            add_measurement_value(packet, &offset, 0x000001, value, 0x00);
        }
        
        *len = offset;
        recalc_iec104_length_and_checksum(packet, len);
    }
}

static void mutate_iec104_specific(uint8_t *packet, size_t *len, enum strategy strat, float rate) {
    iec104_dictionary_t dict;
    init_iec104_dictionary(&dict);
    
    if (*len < IEC104_APCI_LENGTH) return;
    
    switch (strat) {
        case RANDOM:
            if (*len >= IEC104_APCI_LENGTH + IEC104_ASDU_MIN_LENGTH) {
                packet[6] = dict.invalid_type_ids[rand() % 16];
                packet[8] = dict.cause_of_transmission[rand() % 8];
            }
            break;
            
        case BITFLIP:
            for (size_t i = 2; i < *len && i < 10; i++) {
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= (1 << (rand() % 8));
                }
            }
            break;
            
        case OVERFLOW:
            if (*len >= 2) packet[1] = 0xFF;
            if (*len >= IEC104_APCI_LENGTH + IEC104_ASDU_MIN_LENGTH) {
                packet[7] = 0xFF;
                packet[9] = 0xFF;
                packet[10] = 0xFF;
            }
            break;
            
        case DICTIONARY:
            if (*len >= IEC104_APCI_LENGTH + IEC104_ASDU_MIN_LENGTH) {
                packet[6] = dict.invalid_type_ids[rand() % 16];
                packet[8] = dict.cause_of_transmission[rand() % 8];
                if (*len >= IEC104_APCI_LENGTH + 10) {
                    packet[11] = dict.quality_descriptors[rand() % 8];
                }
            }
            break;
            
        case TIME_BASED:
            if (*len >= IEC104_APCI_LENGTH + IEC104_ASDU_MIN_LENGTH + 7) {
                memcpy(packet + *len - 8, dict.time_patterns, 7);
            }
            break;
            
        case SEQUENCE_VIOLATION:
            if (*len >= 4) {
                packet[2] = 0xFF;
                packet[3] = 0xFF;
                packet[4] = 0xFF;
                packet[5] = 0xFF;
            }
            break;
            
        default:
            // Handle any unhandled strategies
            break;
    }
}

static void iec104_mutate_packet(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session) {
    (void)session;  // Mark unused parameter
    
    mutate_iec104_specific(packet, len, strat, rate);
    
    iec104_dictionary_t dict;
    init_iec104_dictionary(&dict);
    
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
                if (i == 1 || (i >= 6 && i <= 10)) {
                    packet[i] = 0xFF;
                } else {
                    packet[i] += (rand() % 100) + 156;
                }
                break;
                
            case DICTIONARY:
                if (i == 6) packet[i] = dict.invalid_type_ids[rand() % 16];
                else if (i == 8) packet[i] = dict.cause_of_transmission[rand() % 8];
                else if (i >= 11 && i < 27) packet[i] = dict.information_object_addresses[rand() % 16];
                else packet[i] = dict.quality_descriptors[rand() % 8];
                break;
                
            case FORMAT_STRING:
                if (i < *len - 8) {
                    const char *fmt_strings[] = {"%s%s%s", "%n%n%n", "%x%x%x"};
                    const char *inject = fmt_strings[rand() % 3];
                    size_t inject_len = strlen(inject);
                    if (i + inject_len < *len) {
                        memcpy(&packet[i], inject, inject_len);
                        i += inject_len - 1;
                    }
                }
                break;
                
            case TYPE_CONFUSION:
                if (i < *len - 4) {
                    // FIXED: Use safe type conversion instead of pointer casting
                    float f = (float)(packet[i] * 1000);
                    write_float_as_bytes(&packet[i], f);
                }
                break;
                
            case TIME_BASED:
                if (i < *len - 8) {
                    uint64_t timestamp = 0xFFFFFFFFFFFFFFFFULL - (rand() % 1000);
                    write_uint64_as_bytes(&packet[i], timestamp);
                    i += 7;
                }
                break;
                
            case SEQUENCE_VIOLATION:
                if (i >= 2 && i <= 5) {
                    packet[i] = (i == 2 || i == 4) ? 0xFE : 0xFF;
                }
                break;
                
            case PROTOCOL_FUZZING:
                packet[i] ^= 0x55;
                break;
                
            case COMBINATORIAL:
                packet[i] = (dict.invalid_type_ids[rand() % 16] ^ 
                           dict.cause_of_transmission[rand() % 8]) + 
                           dict.quality_descriptors[rand() % 8];
                break;
                
            default:
                // Default mutation for any unhandled strategies
                if ((float)rand() / RAND_MAX < rate) {
                    packet[i] ^= 0xAA;
                }
                break;
        }
    }
    
    if (rand() % 5 == 0) {
        size_t new_len = rand() % BUF_SIZE;
        if (new_len > IEC104_APCI_LENGTH) *len = new_len;
    }
    
    if (*len >= 2) packet[1] = (*len - 2) & 0xFF;
    
    recalc_iec104_length_and_checksum(packet, len);
}

static int analyze_iec104_response(uint8_t *response, int len, session_context_t *session) {
    if (len <= 0) return -1;
    
    if (len < IEC104_APCI_LENGTH) return 1;
    
    if (response[0] != 0x68) return 2;
    
    uint8_t declared_length = response[1];
    if (len != declared_length + 2) return 3;
    
    if (len > IEC104_APCI_LENGTH) {
        uint8_t calculated_csum = calculate_iec104_checksum(response + 2, len - 3);
        uint8_t received_csum = response[len - 1];
        if (calculated_csum != received_csum) return 4;
    }
    
    uint8_t control_byte1 = response[2];
    uint8_t control_byte2 = response[3];
    
    if ((control_byte1 & 0x01) && (control_byte2 & 0x01)) {
        return 5;
    }
    
    if (control_byte1 == 0x07 || control_byte1 == 0x0B || control_byte1 == 0x13) {
        return 6;
    }
    
    if (len > IEC104_APCI_LENGTH) {
        uint8_t type_id = response[6];
        if (type_id == 0x00 || type_id >= 0x80) return 7;
        
        for (int i = 0; i < len - 4; i++) {
            if (response[i] == 0xBA && response[i+1] == 0xAD && 
                response[i+2] == 0xF0 && response[i+3] == 0x0D) {
                return 8;
            }
        }
        
        if (len > 1000) return 9;
    }
    
    if (session) {
        session->last_response = time(NULL);
        if (len >= 4) {
            uint16_t recv_seq = ((response[4] >> 1) | (response[5] << 7)) & 0x7FFF;
            session->transaction_id = recv_seq;
        }
    }
    
    return 0;
}

static protocol_ops_t iec104_ops = {
    .generate_packet = iec104_generate_packet,
    .mutate_packet = iec104_mutate_packet,
    .analyze_response = analyze_iec104_response
};

protocol_ops_t *get_protocol_ops(void) {
    return &iec104_ops;
}
