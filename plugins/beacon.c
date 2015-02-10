/* Copyright © 2014 Phil Stanhope <stanhope@gmail.com>
 *
 * This file is enhancement to gdnsd.
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
 * Beacon config examples

  plugins => {
    reflect => {}
    beacon => {
    node_id => "use2"
    node_ip => "54.91.67.105"
    node_ipv6 => "2600:2001:1:26::199"
    domain => "jisusaiche.info."
    domain_test => "use2.thesaiche.com."
    blackhole => "127.0.0.1"
    blackhole_ipv6 => "::1"
    blackhole_as_refused => false
    relay => true
    relay_edns_client => true
    statsd_enabled => true
    }
  }

 */

#define GDNSD_PLUGIN_NAME beacon

#include "config.h"
#include <gdnsd/plugin.h>
#include <string.h>

#define DYN_BEACON
#define STATSD
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <Judy.h>
#include "hiredis.h"
#include "statsd-client.h"

static void redis_init(uint);
void* dyn_beacon_timer (void * args);
static u_char* convert_qname(const u_char* qdata);

pthread_mutex_t DYN_BEACON_MUTEX = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char event_channel[32];
    char id[5];
    char ip[40];
    char ipV6[46];
    char domain[64];
    char domain_test[64];
    char blackhole_ip[40];
    char blackhole_ipV6[46];
    uint8_t blackhole_as_refused;
    redisContext *redis;
    uint8_t redis_firstinit;
    Pvoid_t event_cache;
    Word_t  event_total;
    Word_t  event_count;
    uint8_t debug;
    uint8_t timer;
    uint8_t relay;
    uint8_t subscribers;
    uint8_t relay_edns_client;
    uint8_t statsd_enabled;
    statsd_link *statsd;
    uint reqs;
    uint refused;
    uint unique;
    uint unique_total;
    uint edns;
    uint edns_unique_total;
    uint edns_total;
    uint8_t heartbeat;
} beacon_config;

Pvoid_t UNIQUE_ARRAY = (Pvoid_t) NULL;
Pvoid_t UNIQUE_ARRAY_TOTAL = (Pvoid_t) NULL;
Pvoid_t EDNS_ARRAY = (Pvoid_t) NULL;
Pvoid_t EDNS_UNIQUE_TOTAL = (Pvoid_t) NULL;

// Global CFG for this plugin
static beacon_config CFG;

// Allow ability to force a REFUSED response, requires knowledge of the wire format and a pointer to the memory for it.
#define DNS_RCODE_REFUSED 5
typedef struct S_PACKED {
    uint16_t id;
    uint8_t flags1;
    uint8_t flags2;
} wire_dns_header_t;

static void redis_init(uint log) {
    CFG.redis = redisConnect("127.0.0.1", 6379);
    if (CFG.redis == NULL || CFG.redis->err) {
	if (CFG.redis) {
	    if (log) log_debug("REDIS_INIT: %s", CFG.redis->errstr);
	    redisFree(CFG.redis);
	    CFG.redis = NULL;
	} else {
	    log_debug("Connection error: can't allocate redis context");
	}
    } else {
	if (log) log_debug("REDIS_INIT: %p", CFG.redis);
	redisEnableKeepAlive(CFG.redis);
    }
}

static double current_time(void) {
    struct timeval tv;
    if (gettimeofday(&tv, 0) < 0 )
	return 0;
    double now = tv.tv_sec + tv.tv_usec / 1e6;
    return now;
}

void* dyn_beacon_timer(void * args V_UNUSED) {
    while(true) {
	sleep (1);

	pthread_mutex_lock(&DYN_BEACON_MUTEX);  // lock the critical section
	Word_t delta = CFG.event_count - CFG.event_total;
	CFG.event_total = CFG.event_count;
	double now = current_time();
	
	log_debug("%f beacon new=%u tot=%u ip=%u ip_total=%u edns=%u unique=%u total=%u", now, (unsigned int)delta, (unsigned int)CFG.event_total, CFG.unique, CFG.unique_total, CFG.edns, CFG.edns_unique_total, CFG.edns_total);
	
#ifdef STATSD
	if (CFG.statsd_enabled && CFG.statsd == NULL) {
	    CFG.statsd = statsd_init_with_namespace("127.0.0.1", 8125, CFG.id);
	}
	
	if (CFG.statsd != NULL) {
#define MAX_LINE_LEN 200
#define PKT_LEN 1400
	    char pkt[PKT_LEN];
	    char tmp[MAX_LINE_LEN];
	    pkt[0]=0;
	    statsd_prepare(CFG.statsd, "dns_reqs", CFG.reqs, "c", 1.0, tmp, MAX_LINE_LEN, 1);
	    strcat(pkt, tmp);
	    statsd_prepare(CFG.statsd, "dns_refused", CFG.refused, "c", 1.0, tmp, MAX_LINE_LEN, 1);
	    strcat(pkt, tmp);
	    statsd_prepare(CFG.statsd, "dns_unique", CFG.unique, "c", 1.0, tmp, MAX_LINE_LEN, 1);
	    strcat(pkt, tmp);
	    statsd_prepare(CFG.statsd, "dns_unique_total", CFG.unique_total, "g", 1.0, tmp, MAX_LINE_LEN, 1);
	    strcat(pkt, tmp);
	    statsd_prepare(CFG.statsd, "dns_edns", CFG.edns, "c", 1.0, tmp, MAX_LINE_LEN, 1);
	    strcat(pkt, tmp);
	    statsd_prepare(CFG.statsd, "dns_edns_total", CFG.edns_total, "g", 1.0, tmp, MAX_LINE_LEN, 1);
	    strcat(pkt, tmp);
	    statsd_prepare(CFG.statsd, "dns_edns_unique", CFG.edns_unique_total, "g", 1.0, tmp, MAX_LINE_LEN, 1);
	    strcat(pkt, tmp);
	    statsd_send(CFG.statsd, pkt);
	}
	CFG.reqs = 0;
	CFG.refused = 0;
	CFG.unique = 0;
	CFG.edns = 0;

	// Clear most recent unique IPs array
	Word_t Rc_word;
	J1FA(Rc_word, UNIQUE_ARRAY);

	// Clear most recent unique IPs array
	J1FA(Rc_word, EDNS_ARRAY);
	(void)Rc_word;

#endif
	if (CFG.redis == NULL) {
	    if (CFG.redis_firstinit) {
		log_debug("Init redis first time");
		redis_init(1);
	    } else {
		redis_init(0);
		if (CFG.redis_firstinit == 0) {
		    if (CFG.redis != NULL) {
			log_debug("Restablished redis localhost connection");
		    }
		}
		else {
		    CFG.redis_firstinit = 0;
		}
	    } 
	}

	if (delta > 0) {

	    // Emit 32K msg at a time
	    char buffer[32*1024];
	    uint bufi = 0;
		
	    // Dump cached events and publish them
	    Word_t cache_count = 0;
	    PWord_t PV = NULL;
	
	    sprintf(buffer, "PUBLISH %s ", CFG.event_channel);
	    bufi = strlen(buffer);
	    buffer[bufi] = 0;

	    Word_t Index;
	    JError_t J_Error;
	    if (((PV) = (PWord_t)JudyLFirst(CFG.event_cache, &Index, &J_Error)) == PJERR) J_E("JudyLFirst", &J_Error);
	    
	    while (PV != NULL) {
		++cache_count;
		char* val = (char*)*PV;
		uint len = strlen(val);
		// fprintf(stderr, "  cached key: %lu val: %s\n", Index, val);
		if (bufi + len > sizeof(buffer)) {
		    // fprintf(stderr, "%s\n", buffer);
		    if (CFG.redis != NULL) {
			redisReply *reply = (redisReply*)redisCommand(CFG.redis, buffer);
			freeReplyObject(reply);
		    }
		    sprintf(buffer, "PUBLISH %s ", CFG.event_channel);
		    bufi = strlen(buffer);
		    buffer[bufi] = 0;
		} 

		// Cache the value
		if (bufi > 30) {
		    buffer[bufi++] = '|';
		}
		memcpy(buffer+bufi, (void*)*PV, len);
		bufi += len;
		buffer[bufi] = 0;
		free((void*)val);
		if (((PV) = (PWord_t)JudyLNext(CFG.event_cache, &Index, &J_Error)) == PJERR) J_E("JudyLNext", &J_Error);
	    }
	
	    // Cleanup
	    Word_t index_size = JudyLFreeArray(&CFG.event_cache, ((PJError_t) NULL)); 
	    (void)index_size;
	    // log_debug("index used %lu bytes of memory, expected=%lu found=%lu total=%lu", index_size, delta, cache_count, CFG.event_total);
		
	    // fprintf(stderr, "%s\n", buffer);
	    if (CFG.redis != NULL) {
		redisReply *reply = (redisReply*)redisCommand(CFG.redis, buffer);
		freeReplyObject(reply);
	    }
	}

	pthread_mutex_unlock(&DYN_BEACON_MUTEX); 

	if (CFG.redis != NULL) {
	    if ((int)now % CFG.heartbeat == 0) {
		pthread_mutex_lock(&DYN_BEACON_MUTEX);  // lock the critical section
		char redis_cmd[256];
		sprintf(redis_cmd, "PUBLISH %s %f,A,%s,%s,DNS_PULSE,SUBSCRIBERS=%d", CFG.event_channel,now,CFG.id,CFG.ip, CFG.subscribers);
		redisReply *reply = redisCommand(CFG.redis, redis_cmd);
		if (reply == NULL) {
		    // Need to re-establish connection
		    redisFree(CFG.redis);
		    CFG.redis = NULL;
		} else {
		    CFG.subscribers = reply->integer;
		    freeReplyObject(reply);
		}
	    }
	    pthread_mutex_unlock(&DYN_BEACON_MUTEX); 
	} 

    }
    return NULL;
}

static u_char* convert_qname(const u_char* qdata) {
    u_int ofs = 0;
    u_int  qdatalen = strlen((const char*)qdata);
    u_int qnameofs = 0;
    u_char* qname = NULL;
    u_int qnamelen = 0;

    /* Determine the length of the QNAME */
    do {
	if (qdata[ofs] == 0) 
	    break; /* root label reached */
	u_int label_len = qdata[ofs];
	// printf("..label_len=%u\n", label_len);
	qnamelen = qnamelen + label_len + 1;
	ofs += qdata[ofs];
    }
    while (++ofs < qdatalen);

    /* Copy query name */
    ofs = 0;
    qnamelen++; /* added space for \0 */
    qname = (u_char*) malloc((qnamelen) * sizeof(char));
    memset(qname, 0, qnamelen);
    do {
	int elemLen = qdata[ofs++];
	if (elemLen == 0) 
	    break; /* root label reached */
	
	while ((elemLen > 0) && (ofs < qdatalen)) {
	    qname[qnameofs++] = qdata[ofs++];
	    elemLen--;
	}
	qname[qnameofs++] = '.';
    }
    while (ofs < qdatalen);
    return qname;
}

static bool config_res(const char* resname, unsigned resname_len V_UNUSED, vscf_data_t* addr, void* data V_UNUSED) {
    if (strcmp(resname, "node_id") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be an IP address or a domainname in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    if (strlen(val) != 4)
		log_fatal("plugin_beacon: resource %s: must be an 4 characters in string form", resname);
	    else {
		strcpy(CFG.id, val);
	    }
	}
    } else if (strcmp(resname, "node_ip") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be an IP address in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.ip, val);
	}
    } else if (strcmp(resname, "node_ipV6") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be an IP address in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    printf("Settingup IPV6 answer %s\n", val);
	    strcpy(CFG.ipV6, val);
	}
    } else if (strcmp(resname, "domain") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be a domainname in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.domain, val);
	}
    } else if (strcmp(resname, "domain_test") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be a domainname in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.domain_test, val);
	}
    } else if (strcmp(resname, "event_channel") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be a channel in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.event_channel, val);
	}
    } else if (strcmp(resname, "blackhole") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be an IP address or a domainname in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.blackhole_ip, val);
	}
    } else if (strcmp(resname, "blackhole_ipV6") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be an IP address or a domainname in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.blackhole_ipV6, val);
	}
    } else if (strcmp(resname, "channel") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be an IP address or a domainname in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.event_channel, val);
	}
    } else if (strcmp(resname, "blackhole_as_refused") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be 'true' or 'false'", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    if (strcmp(val, "true") == 0)
		CFG.blackhole_as_refused = 1;
	}
    } else if (strcmp(resname, "relay") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be 'true' or 'false'", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    if (strcmp(val, "true") == 0)
		CFG.relay = 1;
	}
    } else if (strcmp(resname, "relay_edns_client") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be 'true' or 'false'", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    if (strcmp(val, "true") == 0)
		CFG.relay_edns_client = 1;
	}
    } else if (strcmp(resname, "statsd_enabled") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be 'true' or 'false'", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    if (strcmp(val, "true") == 0)
		CFG.statsd_enabled = 1;
	}
    } else if (strcmp(resname, "heartbeat") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be integer", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    int intval = atoi(val);
	    if (intval > 0) {
		CFG.heartbeat = intval;
	    }
	}
    }
    return 1;
}

// -- END DYN BEACON IMPL ------------------------------------

// -- BEG SIMPLE INLINE DNS RE(QUERY) IMPL ------------------------------------

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
 
//Function Prototypes
void ngethostbyname (const char*, uint8_t, const char*, unsigned char* , int);
void EncodeQname (unsigned char*,unsigned char*);
 
//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;
 
void EncodeQname(unsigned char* dns, unsigned char* host) 
{
    unsigned int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) {
	if(host[i]=='.') 
	    {
		*dns++ = i-lock;
		for(;lock<i;lock++) 
		    {
			*dns++=host[lock];
		    }
		lock++; //or lock=i+1;
	    }
    }
    *dns++='\0';
}

#define ASCII_LINELENGTH 300
#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE  (HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)

void hex_and_ascii_print(register const char *ident, register const u_char *cp, register u_int length);
void hex_and_ascii_print_with_offset(register const char *ident, register const u_char *cp, register u_int length, register u_int oset);

void
hex_and_ascii_print_with_offset(register const char *ident, register const u_char *cp, register u_int length, register u_int oset)
{
  register u_int i;
  register int s1, s2;
  register int nshorts;
  char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
  char asciistuff[ASCII_LINELENGTH+1], *asp;

  nshorts = (int)(length / sizeof(u_short));
  i = 0;
  hsp = hexstuff; asp = asciistuff;
  while (--nshorts >= 0) {
    s1 = *cp++;
    s2 = *cp++;
    (void)snprintf(hsp, sizeof(hexstuff) - (long unsigned int)(hsp - hexstuff),
		   " %02x%02x", s1, s2);
    hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
    *(asp++) = (isgraph(s1) ? s1 : '.');
    *(asp++) = (isgraph(s2) ? s2 : '.');
    i++;
    if (i >= HEXDUMP_SHORTS_PER_LINE) {
      *hsp = *asp = '\0';
      (void)printf("%s0x%04x: %-*s  %s",
		   ident, oset, HEXDUMP_HEXSTUFF_PER_LINE,
		   hexstuff, asciistuff);
      i = 0; hsp = hexstuff; asp = asciistuff;
      oset += HEXDUMP_BYTES_PER_LINE;
    }
  }
  if (length & 1) {
    s1 = *cp++;
    (void)snprintf(hsp, sizeof(hexstuff) - (long unsigned int)(hsp - hexstuff),
		   " %02x", s1);
    hsp += 3;
    *(asp++) = (isgraph(s1) ? s1 : '.');
    ++i;
  }
  if (i > 0) {
    *hsp = *asp = '\0';
    (void)printf("%s0x%04x: %-*s  %s",
		 ident, oset, HEXDUMP_HEXSTUFF_PER_LINE,
		 hexstuff, asciistuff);
  }
}

void hex_and_ascii_print(register const char *ident, register const u_char *cp, register u_int length)
{
  hex_and_ascii_print_with_offset(ident, cp, length, 0);
  fflush(stderr);
}

/*
 * Perform a DNS query by sending a UDP packet. 
 */
void ngethostbyname(const char* client, uint8_t mask, const char *target, unsigned char *host , int query_type)
{
    // printf("ngethostbyname %s client=%s mask=%u target=%s\n", host, client, mask, target);

    unsigned char buf[65536],*qname;
    int i, s;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    dns = (struct DNS_HEADER *)&buf;
    dns->id = (unsigned short) htons(getpid());
    dns->rd = 0;
    dns->tc = 0;
    dns->aa = 0;
    dns->opcode = 0;
    dns->qr = 0; 
    dns->rcode = 0;
    dns->cd = 0;
    dns->ad = 0;
    dns->z = 0;
    dns->ra = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 1;
 
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    EncodeQname(qname, host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    qinfo->qtype = htons( query_type );
    qinfo->qclass = htons(1);
 
    unsigned int packet_len = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);

    /*
    printf("Sending %f data=%p len=%d client=%s mask=%u", current_time(), buf, packet_len, client, mask);
    hex_and_ascii_print("\r\n", buf, packet_len);
    printf("\n");
    */

    uint8_t edns_len = 0;

    if (CFG.relay_edns_client && mask != 0) {

	// Add quick & dirty EDNS0 client subnet for the relay of the request
	edns_len = 22;
	struct sockaddr_in edns;
	memset(&edns,0,sizeof edns);  
	char str_client[40];
	strcpy(str_client, client);
	edns.sin_family = AF_INET;
	inet_aton(str_client, &edns.sin_addr);
	
	const char* edns_info = "\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00";
	memcpy(buf+packet_len, edns_info, 10);
	
	const char* edns_addr_info_24 = "\x0b\x00\x08\x00\x07\x00\x01";
	const char* edns_addr_info_32 = "\x0c\x00\x08\x00\x08\x00\x01";
	memcpy(buf+packet_len+10, mask == 24 ? edns_addr_info_24 : edns_addr_info_32, 7);

	// encode the client mask
	buf[packet_len+17] = mask;
	buf[packet_len+18] = 0;

	// encode the client address, could be a compressed address. Only handlng /24 and /32 properly
	buf[packet_len+19] = edns.sin_addr.s_addr & 0xFF;
	buf[packet_len+20] = (edns.sin_addr.s_addr & 0xFF00)>>8;
	buf[packet_len+21] = (edns.sin_addr.s_addr & 0xFF0000)>>16; 
	if (mask == 32) {
	    buf[packet_len+22] = (edns.sin_addr.s_addr & 0xFF000000)>>24; 
	    edns_len++;
	}
	
    }

    /*
    printf("-- Query Packet len=%d\n", packet_len+edns_len);
    hex_and_ascii_print("\r\n", buf, packet_len+edns_len);
    printf("\n");
    */

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(target);
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
    // printf("ngethostbyname: forwarding query to %s edns_client=%d\n", target, CFG.relay_edns_client);
    if (sendto(s,(char*)buf,packet_len+edns_len,0,(struct sockaddr*)&dest,sizeof(dest)) >= 0) {
	//Receive the answer. We really don't care what it is. 
	recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i);
    } else {
	printf("Error sending proxy'd DNS request\n");
    }

}
 
void plugin_beacon_load_config(vscf_data_t* config, const unsigned num_threads V_UNUSED) {
    gdnsd_dyn_addr_max(1, 1); // only ever returns a single IP from each family

    // Config default values
    CFG.ip[0] = 0;
    CFG.ipV6[0] = 0;
    CFG.id[0] = 0;
    CFG.domain[0] = 0;
    CFG.domain_test[0] = 0;
    CFG.blackhole_ip[0] = 0;
    CFG.blackhole_as_refused = 0;
    CFG.redis = NULL;
    CFG.redis_firstinit = 1;
    CFG.event_cache = (Pvoid_t) NULL;
    CFG.event_total = 0;
    CFG.event_count = 0;
    CFG.debug = 0;
    CFG.timer = 0;
    CFG.relay = 0;
    CFG.relay_edns_client = 0;
    CFG.statsd_enabled = 0;
    CFG.statsd = NULL;
    strcpy(CFG.event_channel, "beacon");
    CFG.reqs = 0;
    CFG.refused = 0;
    CFG.unique = 0;
    CFG.unique_total = 0;
    CFG.edns = 0;
    CFG.edns_total = 0;
    CFG.heartbeat = 10;

    unsigned residx = 0;
    vscf_hash_iterate(config, false, config_res, &residx);

    u_int is_valid = 1;

    if (CFG.id[0] == 0) {
	printf("  'node_id' not specified\n");
	is_valid = 0;
    }
    if (CFG.ip[0] == 0) {
	printf("  'node_ip' not specified\n");
	is_valid = 0;
    }
    if (CFG.ipV6[0] == 0) {
	printf("  'node_ipV6' not specified\n");
    }

    if (CFG.domain[0] == 0) {
	printf("  'domain' not specified\n");
	is_valid = 0;
    }

    if (CFG.blackhole_ip[0] == 0) {
	printf("  'blackhole' not specified\n");
	is_valid = 0;
    }

    if (!is_valid) {
	printf("ERROR: Plugin not configured properly\n");
	exit(1);
    } else {
	log_debug("plugin_beacon: config id=%s ip=%s ipV6=%s domain=%s domain_test=%s blackhole=%s blackhole_ipV6=%s blackhole_as_refused=%s relay=%s statsd=%d channel=%s heartbeat=%d",
		  CFG.id, CFG.ip, CFG.ipV6, CFG.domain, CFG.domain_test, CFG.blackhole_ip, CFG.blackhole_ipV6,
		  CFG.blackhole_as_refused ? "true":"false", 
		  CFG.relay?"true":"false",
		  CFG.statsd_enabled,
		  CFG.event_channel,
		  CFG.heartbeat);
    }

}

int RESCNT = 0;
Pvoid_t RES_CACHE = (PWord_t)NULL;
Pvoid_t RES_REVERSE_CACHE = NULL;

int plugin_beacon_map_res(const char* resname, const uint8_t* origin V_UNUSED) {
    if (resname == NULL) return 0;
    RESCNT++;
    PWord_t PV = NULL;

    JSLG(PV, RES_CACHE, (const uint8_t*)resname);
    if (PV == NULL) {
	JSLI(PV, RES_CACHE, (const uint8_t*)resname);
	*PV = (Word_t)RESCNT;
	PWord_t PV2 = NULL;
	JLI(PV2, RES_REVERSE_CACHE, (Word_t)RESCNT);
	char* val = (char*)malloc(strlen(resname)+1);
	strcpy(val, resname);
	*PV2 = (Word_t)val;
	printf("map_res resname=%s => %d\n", resname, RESCNT);
	
	return RESCNT;
    } else {
	return *PV;
    }

}

pthread_t DNS_TELEMETRY_THREAD;

gdnsd_sttl_t plugin_beacon_resolve(unsigned resnum, const uint8_t* origin V_UNUSED, const client_info_t* cinfo, dyn_result_t* result) {

    PWord_t PV = NULL;
    JLG(PV, RES_REVERSE_CACHE, resnum);
    char* result_ip = CFG.ip;
    uint8_t is_proxy = 0;
    // Determine if we've got an zone level answer for this resolution
    // beacon!IPV4 => give up the IPV4
    // beacon!proxy_IPV4 => give up the IPV4 and 
    if (PV != NULL) {
	result_ip =(char*)*PV;
	char* res = strcmp(result_ip, "proxy_");
	if (res == result_ip) {
	    is_proxy = 1;
	    result_ip += 6;
	}
    }

    // Deferred until iothread init (after potential daemonization)
    if (CFG.timer == 0) {
	pthread_create (&DNS_TELEMETRY_THREAD, NULL, &dyn_beacon_timer, NULL);
	log_info("plugin_beacon: background_timer initialized");
	CFG.timer = 1;
    }

    double network_time = current_time();
    u_int is_valid = 1;
    u_int is_test = 0;
    const u_char* qdata = cinfo->qname+1;
    u_char* qname = convert_qname(qdata);

    // printf("plugin_beacon_resolve is_udp=%u qtype=%u qname=%s\n", cinfo->is_udp, cinfo->qtype, qname);

    char temp[1024];
    strcpy(temp, (char*)qname);
    char* saveptr, *domain;
    char* cid = strtok_r(temp, ".", &saveptr);
    char* cdata = strtok_r(NULL, ".", &saveptr);
    char* beacon = strtok_r(NULL, ".", &saveptr);
    domain = saveptr;

    const char* s_client_info = dmn_logf_anysin(&cinfo->dns_source);
    const char* proxy_client = s_client_info;
    // uint8_t isV6 = cinfo->dns_source.sa.sa_family == AF_INET6 ? 1 :  0;
    // printf("  clientip=%s v6=%u qtype=%u qname=%s\n", s_client_info, isV6, cinfo->qtype, cinfo->qname);

    if (cinfo->qtype == 28) {
      result_ip = CFG.ipV6;
    }

    struct in_addr client_subnet_addr;
    char s_edns_client[DMN_ANYSIN_MAXLEN+1];
    client_subnet_addr.s_addr = cinfo->edns_client.sin.sin_addr.s_addr;
    char* s_edns = inet_ntoa(client_subnet_addr);
    
    if (client_subnet_addr.s_addr == 0)
	strcpy(s_edns_client, "-");
    else {
	sprintf(s_edns_client, "%s/%d", s_edns, cinfo->edns_client_mask);
	proxy_client = s_edns;
    }
	
    if (cid == NULL || cdata == NULL || beacon == NULL) {
	if (domain != NULL && strcmp(domain, CFG.domain) != 0) {
	    is_valid = 0;
	}
    } else  {
	if (domain != NULL && domain[0] == 0) {
	    int cmp_val = strcmp((char*)qname, CFG.domain_test);
	    if (cmp_val == 0) {
		is_test = 1;
	    }
	}
    }

    if (!is_test) {
	// cid can only be 4 characters
	if (strlen(cid) != 4)
	    is_valid = 0;
    
	// cdata can be <= 16 characters. Trim to 16 rather than concluding invalid.
	if (strlen(cdata) > 16)
	    cdata[16] = 0;
    
	// beacon must be 45 characters (e.g. use2ae4160014047f846aab247986cd7d164d21f4ceb5)
	if (strlen(beacon) != 45)
	    is_valid = 0;
    }
    
    // printf("resolve %s => %s\n..resnum=%u\n..cid=%s\n..cdata=%s\n..beacon=%s\n..domain=%s\n..client=%s\n..edns_client=%s\n..is_valid=%d\n..is_test=%d\n..domain_test=%s\n..is_proxy=%d\n", qname, result_ip,resnum,cid,cdata,beacon,domain,s_client, s_edns_client, is_valid, is_test, CFG.domain_test, is_proxy);

    if (is_valid) {
	// Don't publish beacon telemetry if it was for the test domain
	if (!is_test) {
	    pthread_mutex_lock(&DYN_BEACON_MUTEX); 

#ifdef STATSD
	    CFG.reqs++;

	    // Track Client (typically a DNS Recursive) usage
	    Word_t Index = cinfo->dns_source.sin.sin_addr.s_addr;
	    // uint8_t* ch = (uint8_t*)&Index;
	    // ch[3] = 0; // Anon to /24
	    int    Rc_int; 
	    J1T(Rc_int, UNIQUE_ARRAY_TOTAL, Index);
	    if (Rc_int == 0) {
		J1S(Rc_int, UNIQUE_ARRAY_TOTAL, Index);
		CFG.unique_total++;
	    }
	    J1T(Rc_int, UNIQUE_ARRAY, Index);
	    if (Rc_int == 0) {
		J1S(Rc_int, UNIQUE_ARRAY, Index);
		CFG.unique++;
	    }

	    // Track EDNS Usage as well
	    Index = cinfo->edns_client.sin.sin_addr.s_addr;
	    if (Index != 0) {
		CFG.edns_total++;
		J1T(Rc_int, EDNS_UNIQUE_TOTAL, Index);
		if (Rc_int == 0) {
		    CFG.edns_unique_total++;
		    J1S(Rc_int, EDNS_UNIQUE_TOTAL, Index);
		}
		J1T(Rc_int, EDNS_ARRAY, Index);
		if (Rc_int == 0) {
		    J1S(Rc_int, EDNS_ARRAY, Index);
		    CFG.edns++;
		}
	    }

#endif

	    char* val = (char*)malloc(256);
	    sprintf(val, "%f,D,%s,%s,%s,%s,%s,%s,%u,%c", network_time,CFG.id,s_client_info, beacon, cid, cdata, s_edns_client, cinfo->qtype, cinfo->is_udp?'U':'T');
	    // log_debug("%s", val);
	    ++CFG.event_count;
	    JError_t J_Error;
	    if (((PV) = (PWord_t)JudyLIns(&CFG.event_cache, CFG.event_count, &J_Error)) == PJERR) {
		J_E("JudyLIns", &J_Error);
	    } else {
		*PV = (Word_t)val;
	    }
	    pthread_mutex_unlock(&DYN_BEACON_MUTEX); 
	}
	dmn_anysin_t tmpsin;
	gdnsd_anysin_fromstr(result_ip, 0, &tmpsin);
	gdnsd_result_add_anysin(result, &tmpsin); 
        // uint8_t cntmp[256];
        // gdnsd_dname_from_string(cntmp, "jisusaiche.com.", 8);
        // gdnsd_result_add_cname(result, cntmp, origin);

	// maybe we'll be forwarding the ednsclient along
	if (is_proxy && CFG.relay != 0) {
	    ngethostbyname(proxy_client, cinfo->edns_client_mask, result_ip, qname, T_A);
	}

   } else if (CFG.blackhole_as_refused) {
	// REFUSED. Possibly not very kosher. But sort of equivalent of simply dropping the request.
#ifdef STATSD
	pthread_mutex_lock(&DYN_BEACON_MUTEX); 
	CFG.refused++;
	pthread_mutex_unlock(&DYN_BEACON_MUTEX); 
#endif
	((wire_dns_header_t*)cinfo->res_hdr)->flags2 = DNS_RCODE_REFUSED;
    } else {
	// Return blackhole IP with no error
#ifdef STATSD
	pthread_mutex_lock(&DYN_BEACON_MUTEX); 
	CFG.refused++;
	pthread_mutex_unlock(&DYN_BEACON_MUTEX); 
#endif
	char val[256];
	sprintf(val, "%s,%s,%s,%u,%c", s_client_info, qname, s_edns_client, cinfo->qtype, cinfo->is_udp?'U':'T');
	dmn_anysin_t tmpsin;
	if (cinfo->qtype == 28) {
	    log_info("BLACKHOLE V6 %s", val);
	    gdnsd_anysin_fromstr(CFG.blackhole_ipV6, 0, &tmpsin);
	} else {
	    log_info("BLACKHOLE %s", val);
	    gdnsd_anysin_fromstr(CFG.blackhole_ip, 0, &tmpsin);
	}
	gdnsd_result_add_anysin(result, &tmpsin);
    }

    return 0; // GDNSD_STTL_TTL_MAX;
}

