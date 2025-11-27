// fuzzer_protocol_common.c
#include "fuzzer_protocol.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h> 

const strategy_info_t strategy_descriptions[STRATEGY_COUNT] = {
    {"random", "Random byte mutation", 0.05, 0, 1},
    {"bitflip", "Bit flipping attacks", 0.03, 0, 1},
    {"overflow", "Buffer overflow attempts", 0.02, 0, 1},
    {"dictionary", "Known bad values", 0.04, 0, 1},
    {"format", "Format string injection", 0.01, 0, 1},
    {"type", "Type confusion attacks", 0.02, 0, 1},
    {"time", "Time-based manipulations", 0.01, 1, 1},
    {"sequence", "Sequence violation attacks", 0.03, 1, 1},
    {"protocol", "Protocol-specific fuzzing", 0.05, 1, 1},
    {"combinatorial", "Combined attack vectors", 0.06, 1, 1}
};

const protocol_info_t protocol_descriptions[PROTOCOL_COUNT] = {
    {"modbus", MODBUS_PORT, 1, 0, 0, 253},
    {"dnp3", DNP3_PORT, 1, 1, 1, 292},
    {"s7comm", S7COMM_PORT, 1, 1, 1, 480},
    {"iec104", IEC104_PORT, 1, 1, 1, 249},
    {"opcua", OPC_UA_PORT, 1, 1, 0, 65536}
};

const char* strategy_to_string(enum strategy strat) {
    if (strat < 0 || strat >= STRATEGY_COUNT) return "unknown";
    return strategy_descriptions[strat].name;
}

const char* protocol_to_string(enum protocol prot) {
    if (prot < 0 || prot >= PROTOCOL_COUNT) return "unknown";
    return protocol_descriptions[prot].name;
}

int get_protocol_port(enum protocol prot) {
    if (prot < 0 || prot >= PROTOCOL_COUNT) return 0;
    return protocol_descriptions[prot].default_port;
}

int validate_strategy(enum strategy strat) {
    return (strat >= 0 && strat < STRATEGY_COUNT);
}

int validate_protocol(enum protocol prot) {
    return (prot >= 0 && prot < PROTOCOL_COUNT);
}

void init_session_context(session_context_t *session, enum protocol prot) {
    if (!session) return;
    
    memset(session, 0, sizeof(session_context_t));
    session->session_id = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    session->transaction_id = 1;
    session->sequence_number = 1;
    session->pdu_reference = 1;
    session->security_token = 1;
    session->secure_channel_id = session->session_id;
    session->protocol_state = 0;
    session->session_flags = 0;
    session->last_response = time(NULL);
    
    switch (prot) {
        case MODBUS:
            session->state_machine[0] = 0x01;
            break;
        case DNP3:
            session->state_machine[0] = 0x02;
            break;
        case S7COMM:
            session->state_machine[0] = 0x03;
            break;
        case IEC104:
            session->state_machine[0] = 0x04;
            break;
        case OPC_UA:
            session->state_machine[0] = 0x05;
            break;
        default:
            break;
    }
}

void update_fuzzing_stats(fuzzing_stats_t *stats, int anomaly_level) {
    if (!stats) return;
    
    stats->anomalies_detected++;
    stats->last_anomaly = time(NULL);
    
    if (anomaly_level == ANOMALY_TIMEOUT) {
        stats->timeouts_occurred++;
    } else if (anomaly_level >= ANOMALY_PROTOCOL_VIOLATION) {
        stats->protocol_errors++;
        
        if (anomaly_level == ANOMALY_CHECKSUM_FAILURE) {
            stats->checksum_failures++;
        } else if (anomaly_level == ANOMALY_SEQUENCE_ERROR) {
            stats->sequence_violations++;
        } else if (anomaly_level == ANOMALY_MEMORY_CORRUPTION || 
                   anomaly_level == ANOMALY_BUFFER_OVERFLOW) {
            stats->memory_anomalies++;
        }
        
        if (anomaly_level >= ANOMALY_CRITICAL) {
            stats->crashes_triggered++;
        }
    }
}

void reset_fuzzing_stats(fuzzing_stats_t *stats) {
    if (!stats) return;
    
    memset(stats, 0, sizeof(fuzzing_stats_t));
    stats->session_start = time(NULL);
}

void print_fuzzing_stats(const fuzzing_stats_t *stats) {
    if (!stats) return;
    
    time_t now = time(NULL);
    double session_duration = difftime(now, stats->session_start);
    double packets_per_second = (session_duration > 0) ? 
        (double)stats->packets_sent / session_duration : 0.0;
    
    printf("\n=== FUZZING STATISTICS ===\n");
    printf("Session Duration: %.2f seconds\n", session_duration);
    printf("Packets Sent: %u (%.2f pps)\n", stats->packets_sent, packets_per_second);
    printf("Anomalies Detected: %u\n", stats->anomalies_detected);
    printf("Crashes Triggered: %u\n", stats->crashes_triggered);
    printf("Timeouts Occurred: %u\n", stats->timeouts_occurred);
    printf("Protocol Errors: %u\n", stats->protocol_errors);
    printf("Memory Anomalies: %u\n", stats->memory_anomalies);
    printf("Sequence Violations: %u\n", stats->sequence_violations);
    printf("Checksum Failures: %u\n", stats->checksum_failures);
    
    if (stats->anomalies_detected > 0) {
        double anomaly_rate = (double)stats->anomalies_detected / stats->packets_sent * 100.0;
        printf("Anomaly Rate: %.2f%%\n", anomaly_rate);
    }
    
    if (stats->last_anomaly > 0) {
        double time_since_anomaly = difftime(now, stats->last_anomaly);
        printf("Time Since Last Anomaly: %.2f seconds\n", time_since_anomaly);
    }
}
