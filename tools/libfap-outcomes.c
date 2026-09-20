#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fap.h"

static void hex_bytes(const char *value, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    if (!value) return;
    for (index = 0; index < length; ++index) {
        unsigned char byte = (unsigned char)value[index];
        putchar(digits[byte >> 4]);
        putchar(digits[byte & 0x0f]);
    }
}

static void hex_string(const char *value)
{
    if (value) hex_bytes(value, strlen(value));
}

static const char *error_name(fap_error_code_t error)
{
    static const char *const names[] = {
        "packet_no", "packet_short", "packet_nobody",
        "srccall_noax25", "srccall_badchars",
        "dstpath_toomany", "dstcall_none", "dstcall_noax25",
        "digicall_noax25", "digicall_badchars",
        "timestamp_inv_loc", "timestamp_inv_obj", "timestamp_inv_sta",
        "timestamp_inv_gpgga", "timestamp_inv_gpgll", "packet_invalid",
        "nmea_inv_cval", "nmea_large_ew", "nmea_large_ns", "nmea_inv_sign",
        "nmea_inv_cksum", "gprmc_fewfields", "gprmc_nofix",
        "gprmc_inv_time", "gprmc_inv_date", "gprmc_date_out",
        "gpgga_fewfields", "gpgga_nofix", "gpgll_fewfields", "gpgll_nofix",
        "nmea_unsupp", "obj_short", "obj_inv", "obj_dec_err", "item_short",
        "item_inv", "item_dec_err", "loc_short", "loc_inv", "loc_large",
        "loc_amb_inv", "mice_short", "mice_inv", "mice_inv_info",
        "mice_amb_large", "mice_amb_inv", "mice_amb_odd", "comp_inv",
        "comp_short", "msg_inv", "wx_unsupp", "user_unsupp", "dx_inv_src",
        "dx_inf_freq", "dx_no_dx", "tlm_inv", "tlm_large", "tlm_unsupp",
        "exp_unsupp", "sym_inv_table", "not_implemented", "nmea_nofields",
        "no_aprs"
    };
    size_t count = sizeof(names) / sizeof(names[0]);
    return (unsigned int)error < count ? names[error] : "unknown";
}

static const char *type_name(fap_packet_type_t type)
{
    switch (type) {
    case fapLOCATION:
    case fapMICE:
    case fapNMEA: return "location";
    case fapOBJECT: return "object";
    case fapITEM: return "item";
    case fapWX: return "wx";
    case fapMESSAGE: return "message";
    case fapCAPABILITIES: return "capabilities";
    case fapSTATUS: return "status";
    case fapTELEMETRY: return "telemetry";
    case fapTELEMETRY_MESSAGE: return "telemetry-message";
    case fapDX_SPOT: return "dx";
    case fapEXPERIMENTAL: return "experimental";
    }
    return "unknown";
}

static void optional_double(const double *value)
{
    if (value) printf("%.17g", *value);
}

static void optional_uint(const unsigned int *value)
{
    if (value) printf("%u", *value);
}

static void optional_short(const short *value)
{
    if (value) printf("%d", (int)*value);
}

int main(int argc, char **argv)
{
    FILE *dataset;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;

    if (argc != 2) {
        fprintf(stderr, "usage: libfap-outcomes DATASET\n");
        return 2;
    }
    dataset = fopen(argv[1], "rb");
    if (!dataset) {
        perror(argv[1]);
        return 2;
    }
    fap_init();
    while ((length = getline(&line, &capacity, dataset)) >= 0) {
        fap_packet_t *packet;
        fap_wx_report_t *weather;
        fap_telemetry_t *telemetry;

        if (length > 0 && line[length - 1] == '\n') --length;
        packet = fap_parseaprs(line, (unsigned int)length, 0);
        if (!packet) {
            fprintf(stderr, "libfap returned NULL\n");
            free(line);
            fclose(dataset);
            fap_cleanup();
            return 3;
        }
        weather = packet->wx_report;
        telemetry = packet->telemetry;

        printf("%d\t", packet->error_code == NULL);
        if (packet->error_code) fputs(error_name(*packet->error_code), stdout);
        putchar('\t');
        if (packet->type) fputs(type_name(*packet->type), stdout);
        putchar('\t'); optional_double(packet->latitude);
        putchar('\t'); optional_double(packet->longitude);
        putchar('\t'); if (packet->symbol_table) printf("%u", (unsigned char)packet->symbol_table);
        putchar('\t'); if (packet->symbol_code) printf("%u", (unsigned char)packet->symbol_code);
        putchar('\t'); optional_uint(packet->course);
        putchar('\t'); optional_double(packet->speed);
        putchar('\t'); optional_double(packet->altitude);
        putchar('\t'); optional_uint(packet->pos_ambiguity);
        putchar('\t'); optional_short(packet->messaging);
        putchar('\t'); hex_string(packet->destination);
        putchar('\t'); hex_string(packet->message);
        putchar('\t'); hex_string(packet->message_id);
        putchar('\t'); hex_string(packet->message_ack);
        putchar('\t'); hex_string(packet->message_nack);
        putchar('\t'); if (telemetry) optional_uint(telemetry->seq);
        putchar('\t'); if (telemetry) optional_double(telemetry->val1);
        putchar('\t'); if (telemetry) optional_double(telemetry->val2);
        putchar('\t'); if (telemetry) optional_double(telemetry->val3);
        putchar('\t'); if (telemetry) optional_double(telemetry->val4);
        putchar('\t'); if (telemetry) optional_double(telemetry->val5);
        putchar('\t'); if (telemetry) hex_bytes(telemetry->bits, sizeof(telemetry->bits));
        putchar('\t'); if (weather) optional_uint(weather->wind_dir);
        putchar('\t'); if (weather) optional_double(weather->wind_speed);
        putchar('\t'); if (weather) optional_double(weather->wind_gust);
        putchar('\t'); if (weather) optional_double(weather->temp);
        putchar('\t'); if (weather) optional_double(weather->temp_in);
        putchar('\t'); if (weather) optional_uint(weather->humidity);
        putchar('\t'); if (weather) optional_uint(weather->humidity_in);
        putchar('\t'); if (weather) optional_double(weather->pressure);
        putchar('\t'); if (weather) optional_double(weather->rain_1h);
        putchar('\t'); if (weather) optional_double(weather->rain_24h);
        putchar('\t'); if (weather) optional_double(weather->rain_midnight);
        putchar('\t'); if (weather) optional_double(weather->snow_24h);
        putchar('\t'); if (weather) optional_uint(weather->luminosity);
        putchar('\t'); if (weather) hex_string(weather->soft);
        putchar('\t'); hex_bytes(packet->comment, packet->comment_len);
        printf("\t%d\n", weather != NULL);
        fap_free(packet);
    }
    free(line);
    fclose(dataset);
    fap_cleanup();
    return 0;
}
