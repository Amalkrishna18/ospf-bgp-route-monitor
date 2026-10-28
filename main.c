
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#define MAX_TRACKED_PREFIXES 256
#define MAX_TRACKED_LSAS 512

struct lsa_record {
    unsigned int lsa_type;
    unsigned int link_state_id;
    unsigned int advertising_router;
    unsigned int sequence_number;
};

static struct lsa_record tracked_lsas[MAX_TRACKED_LSAS];
static unsigned int tracked_lsa_count = 0;

static char announced_prefixes[MAX_TRACKED_PREFIXES][INET_ADDRSTRLEN + 4];
static unsigned int announced_prefix_count = 0;
static unsigned int announcement_count = 0;
static unsigned int withdrawal_count = 0;
static unsigned int notification_count = 0;
static unsigned int ospf_lsa_updates = 0;
static unsigned int ospf_lsas_seen = 0;
/* Print events to the terminal and append them to a log file. */
static void log_event(const char *format, ...)
{
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    char timestamp[32];

    if (local_time != NULL) {
        strftime(timestamp, sizeof(timestamp),
                 "%Y-%m-%d %H:%M:%S", local_time);
    } else {
        snprintf(timestamp, sizeof(timestamp), "time-unavailable");
    }

    va_list args;

    printf("[%s] ", timestamp);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    FILE *log_file = fopen("route_monitor.log", "a");

    if (log_file != NULL) {
        fprintf(log_file, "[%s] ", timestamp);

        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);

        fclose(log_file);
    } else {
        perror("Could not open route_monitor.log");
    }
}

/* Decode and process IPv4 prefixes from BGP UPDATE messages. */
static int print_ipv4_prefixes(
    const unsigned char *data,
    unsigned int length,
    const char *label)
{
    unsigned int offset = 0;

    while (offset < length) {
        unsigned int prefix_len = data[offset++];

        if (prefix_len > 32) {
            log_event("ALERT: Invalid IPv4 prefix length\n");
            return -1;
        }

        unsigned int bytes = (prefix_len + 7) / 8;

        if (bytes > length - offset) {
            log_event("ALERT: Incomplete IPv4 prefix\n");
            return -1;
        }

        unsigned char address[4] = {0};

        for (unsigned int i = 0; i < bytes; i++) {
            address[i] = data[offset + i];
        }

        /* Clear host bits in a partially occupied final byte. */
        if (bytes > 0 && prefix_len % 8 != 0) {
            address[bytes - 1] &=
                (unsigned char)(0xFF << (8 - prefix_len % 8));
        }

        char ip_address[INET_ADDRSTRLEN];

        if (inet_ntop(AF_INET, address, ip_address,
                      sizeof(ip_address)) == NULL) {
            log_event("ALERT: Could not decode IPv4 prefix\n");
            return -1;
        }

        log_event("%s: %s/%u\n", label, ip_address, prefix_len);

        if (strcmp(label, "Announced route") == 0 ||
            strcmp(label, "Withdrawn route") == 0) {

            char prefix[INET_ADDRSTRLEN + 4];

            snprintf(prefix, sizeof(prefix), "%s/%u",
                     ip_address, prefix_len);

            if (strcmp(label, "Announced route") == 0) {
                announcement_count++;
            } else {
                withdrawal_count++;
            }

            int found = -1;

            for (unsigned int i = 0;
                 i < announced_prefix_count; i++) {
                if (strcmp(announced_prefixes[i], prefix) == 0) {
                    found = (int)i;
                    break;
                }
            }

            if (strcmp(label, "Announced route") == 0) {
                if (found >= 0) {
                    log_event(
                        "ALERT: Repeated prefix announcement: %s\n",
                        prefix);
                } else if (announced_prefix_count <
                           MAX_TRACKED_PREFIXES) {
                    strcpy(
                        announced_prefixes[announced_prefix_count],
                        prefix);

                    announced_prefix_count++;

                    log_event("Total tracked prefixes: %u\n",
                              announced_prefix_count);
                } else {
                    log_event(
                        "ALERT: Prefix tracking limit reached\n");
                }
            } else {
                if (found >= 0) {
                    for (unsigned int i = (unsigned int)found;
                         i + 1 < announced_prefix_count; i++) {
                        strcpy(announced_prefixes[i],
                               announced_prefixes[i + 1]);
                    }

                    announced_prefix_count--;

                    log_event("Route removed from tracking: %s\n",
                              prefix);
                    log_event("Total tracked prefixes: %u\n",
                              announced_prefix_count);
                } else {
                    log_event(
                        "Withdrawn prefix was not in tracking: %s\n",
                        prefix);
                }
            }
        }

        offset += bytes;
    }

    return 0;
}

/* Parse the withdrawn routes, path attributes and announced routes
   in a BGP UPDATE message body. */
static void parse_bgp_update(
    const unsigned char *data,
    unsigned int length)
{
    if (length < 4) {
        log_event("ALERT: BGP UPDATE body is incomplete\n");
        return;
    }

    unsigned int withdrawn_len =
        ((unsigned int)data[0] << 8) | data[1];

    unsigned int offset = 2;

    if (withdrawn_len > length - offset) {
        log_event("ALERT: Invalid withdrawn-routes length\n");
        return;
    }

    if (withdrawn_len > 0) {
        if (print_ipv4_prefixes(
                data + offset, withdrawn_len,
                "Withdrawn route") < 0) {
            return;
        }
    } else {
        printf("  Withdrawn routes: none\n");
    }

    offset += withdrawn_len;

    if (length - offset < 2) {
        log_event("ALERT: Missing path-attributes length\n");
        return;
    }

    unsigned int attributes_len =
        ((unsigned int)data[offset] << 8) | data[offset + 1];

    offset += 2;

    if (attributes_len > length - offset) {
        log_event("ALERT: Invalid path-attributes length\n");
        return;
    }

    offset += attributes_len;

    if (offset < length) {
        print_ipv4_prefixes(
            data + offset, length - offset,
            "Announced route");
    } else {
        printf("  Announced routes: none\n");
    }
}

/* Validate and identify a BGP message carried in TCP payload. */
static void check_bgp_header(
    const unsigned char *data,
    unsigned int length)
{
    if (length < 19) {
        printf("  BGP candidate: TCP payload too short for header\n");
        return;
    }

    int marker_valid = 1;

    for (int i = 0; i < 16; i++) {
        if (data[i] != 0xFF) {
            marker_valid = 0;
            break;
        }
    }

    unsigned int bgp_length =
        ((unsigned int)data[16] << 8) | data[17];

    unsigned int message_type = data[18];

    if (!marker_valid || bgp_length < 19 ||
        bgp_length > 4096 || bgp_length > length ||
        message_type < 1 || message_type > 5) {
        log_event("ALERT: Invalid or incomplete BGP header\n");
        return;
    }

    if ((message_type == 1 && bgp_length < 29) ||
        (message_type == 2 && bgp_length < 23) ||
        (message_type == 3 && bgp_length < 21) ||
        (message_type == 4 && bgp_length != 19) ||
        (message_type == 5 && bgp_length < 23)) {
        log_event(
            "ALERT: Invalid BGP message length for type %u\n",
            message_type);
        return;
    }

    const char *type_name;

    switch (message_type) {
        case 1: type_name = "OPEN"; break;
        case 2: type_name = "UPDATE"; break;
        case 3: type_name = "NOTIFICATION"; break;
        case 4: type_name = "KEEPALIVE"; break;
        case 5: type_name = "ROUTE-REFRESH"; break;
        default: type_name = "UNKNOWN"; break;
    }

    printf("  BGP message     : %s\n", type_name);
    printf("  BGP length      : %u bytes\n", bgp_length);

    if (message_type == 2) {
        parse_bgp_update(data + 19, bgp_length - 19);
        printf("  BGP UPDATE detected: routing information present.\n");
    }

    if (message_type == 3) {
        notification_count++;

        log_event("ALERT: BGP NOTIFICATION received!\n");
        log_event(
            "WARNING: BGP session may be closing due to a protocol error.\n");
    }
}

static void parse_ospf_ls_update(
    const unsigned char *ospf,
    unsigned int ospf_length)
{
    /* OSPF header is 24 bytes */
    if (ospf_length < 28) {
        log_event("ALERT: OSPF Link-State Update is incomplete\n");
        return;
    }

    /* LSA count is stored after the 24-byte OSPF header */
    unsigned int lsa_count =
        ((unsigned int)ospf[24] << 24) |
        ((unsigned int)ospf[25] << 16) |
        ((unsigned int)ospf[26] << 8) |
        (unsigned int)ospf[27];
    if (lsa_count > (ospf_length - 28) / 20) {
        log_event("ALERT: LSA count exceeds available packet data\n");
        return;
    }
    ospf_lsa_updates++;

    log_event("OSPF Link-State Update detected: %u LSA(s)\n",
              lsa_count);

    unsigned int offset = 28;

    for (unsigned int i = 0; i < lsa_count; i++) {
        /* Each LSA has a 20-byte header */
        if (offset > ospf_length ||
            ospf_length - offset < 20) {
            log_event("ALERT: Incomplete LSA header\n");
            return;
        }

        const unsigned char *lsa = ospf + offset;

        unsigned int lsa_type = lsa[3];

        char link_state_id[INET_ADDRSTRLEN];
        char advertising_router[INET_ADDRSTRLEN];

        unsigned int lsa_id =
            ((unsigned int)lsa[4] << 24) |
            ((unsigned int)lsa[5] << 16) |
            ((unsigned int)lsa[6] << 8) |
            (unsigned int)lsa[7];

        unsigned int router_id =
            ((unsigned int)lsa[8] << 24) |
            ((unsigned int)lsa[9] << 16) |
            ((unsigned int)lsa[10] << 8) |
            (unsigned int)lsa[11];

        struct in_addr id_addr;
        struct in_addr router_addr;

        id_addr.s_addr = htonl(lsa_id);
        router_addr.s_addr = htonl(router_id);

        if (inet_ntop(AF_INET, &id_addr, link_state_id,
                      sizeof(link_state_id)) == NULL ||
            inet_ntop(AF_INET, &router_addr, advertising_router,
                      sizeof(advertising_router)) == NULL) {
            log_event("ALERT: Could not decode LSA identifiers\n");
            return;
        }

        unsigned int lsa_length =
            ((unsigned int)lsa[18] << 8) | lsa[19];
        
        unsigned int lsa_sequence =
            ((unsigned int)lsa[12] << 24) |
            ((unsigned int)lsa[13] << 16) |
            ((unsigned int)lsa[14] << 8) |
            (unsigned int)lsa[15];
          
        if (lsa_length < 24 ||
            lsa_length > ospf_length - offset) {
            log_event("ALERT: Invalid LSA length: %u\n",
                      lsa_length);
            return;
        }
 
        int found_lsa = -1;

for (unsigned int j = 0; j < tracked_lsa_count; j++) {
    if (tracked_lsas[j].lsa_type == lsa_type &&
        tracked_lsas[j].link_state_id == lsa_id &&
        tracked_lsas[j].advertising_router == router_id) {
        found_lsa = (int)j;
        break;
    }
}

if (found_lsa >= 0) {
    if (tracked_lsas[found_lsa].sequence_number != lsa_sequence) {
        log_event(
            "ALERT: OSPF LSA sequence changed: "
            "type %u, Link-State ID %s, router %s, "
            "old sequence 0x%08X, new sequence 0x%08X\n",
            lsa_type, link_state_id, advertising_router,
            tracked_lsas[found_lsa].sequence_number,
            lsa_sequence);

        tracked_lsas[found_lsa].sequence_number = lsa_sequence;
    }
} else if (tracked_lsa_count < MAX_TRACKED_LSAS) {
    tracked_lsas[tracked_lsa_count].lsa_type = lsa_type;
    tracked_lsas[tracked_lsa_count].link_state_id = lsa_id;
    tracked_lsas[tracked_lsa_count].advertising_router = router_id;
    tracked_lsas[tracked_lsa_count].sequence_number = lsa_sequence;
    tracked_lsa_count++;
} else {
    log_event("WARNING: OSPF LSA tracking table is full\n");
}

        ospf_lsas_seen++;

        log_event("  LSA type: %u, Link-State ID: %s, "
                  "Advertising Router: %s, Length: %u bytes\n",
                  lsa_type, link_state_id,
                  advertising_router, lsa_length);

        offset += lsa_length;
    }
}


/* Inspect Ethernet frames and identify IPv4, TCP/BGP and OSPF traffic. */
static void packet_handler(
    unsigned char *user,
    const struct pcap_pkthdr *header,
    const unsigned char *packet)
{
    (void)user;

    printf("Packet captured: %u bytes\n", header->len);

    if (header->caplen < 14) {
        printf("  Short Ethernet frame\n\n");
        return;
    }

    unsigned int ether_type =
        ((unsigned int)packet[12] << 8) | packet[13];

    if (ether_type != 0x0800) {
        printf("  Non-IPv4 Ethernet frame\n\n");
        return;
    }

    const unsigned char *ip = packet + 14;
    unsigned int available = header->caplen - 14;

    if (available < 20 || (ip[0] >> 4) != 4) {
        printf("  Invalid or incomplete IPv4 header\n\n");
        return;
    }

    unsigned int ihl = (ip[0] & 0x0F) * 4;

    if (ihl < 20 || ihl > available) {
        printf("  Invalid IPv4 header length\n\n");
        return;
    }

    unsigned int total_ip_length =
        ((unsigned int)ip[2] << 8) | ip[3];

    if (total_ip_length < ihl || total_ip_length > available) {
        printf("  Invalid or incomplete IPv4 packet\n\n");
        return;
    }

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, ip + 12, src, sizeof(src)) == NULL ||
        inet_ntop(AF_INET, ip + 16, dst, sizeof(dst)) == NULL) {
        printf("  Could not decode IP addresses\n\n");
        return;
    }

    printf("  Source IP      : %s\n", src);
    printf("  Destination IP : %s\n", dst);

    unsigned int protocol = ip[9];

    /* TCP: inspect packets that use BGP port 179. */
    if (protocol == 6) {
        printf("  Protocol       : TCP\n");

        if (total_ip_length - ihl < 20) {
            printf("  Invalid or incomplete TCP header\n\n");
            return;
        }

        const unsigned char *tcp = ip + ihl;

        unsigned int tcp_header_length =
            (tcp[12] >> 4) * 4;

        if (tcp_header_length < 20 ||
            tcp_header_length > total_ip_length - ihl) {
            printf("  Invalid TCP header length\n\n");
            return;
        }

        unsigned int source_port =
            ((unsigned int)tcp[0] << 8) | tcp[1];

        unsigned int destination_port =
            ((unsigned int)tcp[2] << 8) | tcp[3];

        if (source_port == 179 || destination_port == 179) {
            printf("  BGP candidate : TCP port 179 detected\n");

            unsigned int tcp_payload_length =
                total_ip_length - ihl - tcp_header_length;

            if (tcp_payload_length > 0) {
                check_bgp_header(
                    tcp + tcp_header_length,
                    tcp_payload_length);
            } else {
                printf("  No TCP payload to inspect\n");
            }
        }
    }

    /* OSPF uses IP protocol number 89. */
    else if (protocol == 89) {
        printf("  Protocol       : OSPF\n");

        if (total_ip_length < ihl + 24) {
            printf("  OSPF packet is incomplete\n\n");
            return;
        }

        const unsigned char *ospf = ip + ihl;

        unsigned int ospf_length =
            ((unsigned int)ospf[2] << 8) | ospf[3];

        if (ospf[0] != 2 ||
            ospf_length < 24 ||
            ospf_length > total_ip_length - ihl) {
            printf("  OSPF header is incomplete or invalid\n\n");
            return;
        }

        switch (ospf[1]) {
            case 1:
                printf("  OSPF message   : Hello\n");
                break;
            case 2:
                printf("  OSPF message   : Database Description\n");
                break;
            case 3:
                printf("  OSPF message   : Link-State Request\n");
                break;
            case 4:
                printf("  OSPF message   : Link-State Update\n");
                parse_ospf_ls_update(ospf, ospf_length);
                break;
            case 5:
                printf("  OSPF message   : Link-State Acknowledgment\n");
                break;
            default:
                printf("  OSPF message   : Unknown type %u\n",
                       ospf[1]);
                break;
        }
    } else {
        printf("  IP protocol    : %u\n", protocol);
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s capture.pcap\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Cannot open capture: %s\n", errbuf);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr,
                "This version requires Ethernet captures.\n");
        pcap_close(handle);
        return 1;
    }

    printf("Reading capture: %s\n\n", argv[1]);

    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int result;

    while ((result = pcap_next_ex(
                handle, &header, &packet)) == 1) {
        packet_handler(NULL, header, packet);
    }

    if (result == -1) {
        fprintf(stderr, "Capture read error: %s\n",
                pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);

    printf("\n========== ROUTE MONITOR SUMMARY ==========\n");
    printf("Total prefixes currently tracked: %u\n",
           announced_prefix_count);
    printf("Route announcements processed: %u\n",
           announcement_count);
    printf("Route withdrawals processed: %u\n",
           withdrawal_count);
    printf("BGP notifications detected: %u\n",
           notification_count);
    printf("===========================================\n");
    printf("Finished reading capture.\n");

    return 0;
}

