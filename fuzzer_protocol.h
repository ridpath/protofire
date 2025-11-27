// fuzzer_protocol.h
#ifndef FUZZER_PROTOCOL_H
#define FUZZER_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define BUF_SIZE 4096
#define MAX_THREADS 64
#define TIMEOUT_SEC 2
#define MODBUS_PORT 502
#define DNP3_PORT 20000
#define S7COMM_PORT 102
#define IEC104_PORT 2404
#define OPC_UA_PORT 4840

enum strategy {
    RANDOM, 
    BITFLIP, 
    OVERFLOW, 
    DICTIONARY,
    FORMAT_STRING, 
    TYPE_CONFUSION, 
    TIME_BASED,
    SEQUENCE_VIOLATION, 
    PROTOCOL_FUZZING, 
    COMBINATORIAL,
    STRATEGY_COUNT
};

enum protocol {
    MODBUS,
    DNP3, 
    S7COMM,
    IEC104,
    OPC_UA,
    PROTOCOL_COUNT
};

enum anomaly_level {
    ANOMALY_NONE = 0,
    ANOMALY_TIMEOUT = -1,
    ANOMALY_PROTOCOL_VIOLATION = 1,
    ANOMALY_LENGTH_VIOLATION = 2,
    ANOMALY_CHECKSUM_FAILURE = 3,
    ANOMALY_FUNCTION_ERROR = 4,
    ANOMALY_SEQUENCE_ERROR = 5,
    ANOMALY_STATE_ERROR = 6,
    ANOMALY_MEMORY_CORRUPTION = 7,
    ANOMALY_BUFFER_OVERFLOW = 8,
    ANOMALY_FORMAT_ERROR = 9,
    ANOMALY_TYPE_ERROR = 10,
    ANOMALY_SECURITY_ERROR = 11,
    ANOMALY_CRITICAL = 12
};

typedef struct {
    uint32_t session_id;
    uint16_t transaction_id;
    uint8_t state_machine[256];
    time_t last_response;
    uint32_t sequence_number;
    uint16_t pdu_reference;
    uint8_t security_token;
    uint32_t secure_channel_id;
    uint8_t protocol_state;
    uint64_t session_flags;
} session_context_t;

typedef struct {
    uint32_t packets_sent;
    uint32_t anomalies_detected;
    uint32_t crashes_triggered;
    uint32_t timeouts_occurred;
    uint32_t protocol_errors;
    uint32_t memory_anomalies;
    uint32_t sequence_violations;
    uint32_t checksum_failures;
    time_t session_start;
    time_t last_anomaly;
} fuzzing_stats_t;

typedef struct {
    const char *name;
    const char *description;
    float default_rate;
    int requires_state;
    int supports_readonly;
} strategy_info_t;

typedef struct {
    const char *name;
    int default_port;
    int supports_readonly;
    int requires_session;
    int has_checksum;
    int max_pdu_size;
} protocol_info_t;

typedef struct protocol_ops {
    void (*generate_packet)(uint8_t *packet, size_t *len, int is_initial, int read_only, session_context_t *session);
    void (*mutate_packet)(uint8_t *packet, size_t *len, enum strategy strat, float rate, session_context_t *session);
    int (*analyze_response)(uint8_t *response, int len, session_context_t *session);
    void (*init_session)(session_context_t *session);
    void (*cleanup_session)(session_context_t *session);
    int (*validate_packet)(const uint8_t *packet, size_t len);
    const char* (*get_strategy_name)(enum strategy strat);
    const char* (*get_anomaly_description)(int anomaly_code);
} protocol_ops_t;

extern const strategy_info_t strategy_descriptions[STRATEGY_COUNT];
extern const protocol_info_t protocol_descriptions[PROTOCOL_COUNT];

const char* strategy_to_string(enum strategy strat);
const char* protocol_to_string(enum protocol prot);
int get_protocol_port(enum protocol prot);
int validate_strategy(enum strategy strat);
int validate_protocol(enum protocol prot);

void init_session_context(session_context_t *session, enum protocol prot);
void update_fuzzing_stats(fuzzing_stats_t *stats, int anomaly_level);
void reset_fuzzing_stats(fuzzing_stats_t *stats);
void print_fuzzing_stats(const fuzzing_stats_t *stats);

#endif
