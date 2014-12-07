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

#define GDNSD_PLUGIN_NAME beacon

#include "config.h"
#include <gdnsd/plugin.h>
#include <string.h>

#define DYN_BEACON
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <Judy.h>
#include "hiredis.h"

static void redis_init(void);
void* dyn_beacon_timer (void * args);
static u_char* convert_qname(const u_char* qdata);

pthread_mutex_t DYN_BEACON_MUTEX = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char event_channel[32];
    char id[5];
    char ip[40];
    char domain[64];
    char domain_test[64];
    char blackhole_ip[40];
    uint8_t blackhole_as_refused;
    redisContext *redis;
    Pvoid_t event_cache;
    Word_t  event_total;
    Word_t  event_count;
    uint8_t debug;
    uint8_t timer;
    uint8_t relay;
} beacon_config;

// Global CFG for this plugin
static beacon_config CFG;

// Allow ability to force a REFUSED response, requires knowledge of the wire format and a pointer to the memory for it.
#define DNS_RCODE_REFUSED 5
typedef struct S_PACKED {
    uint16_t id;
    uint8_t flags1;
    uint8_t flags2;
} wire_dns_header_t;

static void redis_init(void) {
    CFG.redis = redisConnect("127.0.0.1", 6379);
    if (CFG.redis == NULL || CFG.redis->err) {
	if (CFG.redis) {
	    log_debug("Connection error: %s\n", CFG.redis->errstr);
	    redisFree(CFG.redis);
	    CFG.redis = NULL;
	} else {
	    log_debug("Connection error: can't allocate redis context\n");
	}
    } else {
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

void* dyn_beacon_timer (void * args V_UNUSED) {
    while(true) {
	sleep (1);

	pthread_mutex_lock(&DYN_BEACON_MUTEX);  // lock the critical section
	Word_t delta = CFG.event_count - CFG.event_total;
	CFG.event_total = CFG.event_count;

	log_debug("%f beacon new=%u tot=%u", current_time(), (unsigned int)delta, (unsigned int)CFG.event_total);
	
	if (delta > 0) {

	    if (CFG.redis == NULL) {
	        redis_init();
	    }

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
    } else if (strcmp(resname, "blackhole") == 0) {
	if (vscf_get_type(addr) != VSCF_SIMPLE_T)
	    log_fatal("plugin_beacon: resource %s: must be an IP address or a domainname in string form", resname);
	else {
	    const char* val = vscf_simple_get_data(addr);
	    strcpy(CFG.blackhole_ip, val);
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
void ngethostbyname (char*, uint8_t, const char*, unsigned char* , int);
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
void ngethostbyname(char* client, uint8_t mask, const char *target, unsigned char *host , int query_type)
{
    printf("ngethostbyname %s client=%s mask=%u target=%s\n", host, client, mask, target);

    unsigned char buf[65536],*qname;
    int i, s;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    dns = (struct DNS_HEADER *)&buf;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; 
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 0;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 1;
 
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    EncodeQname(qname, host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
    qinfo->qtype = htons( query_type );
    qinfo->qclass = htons(1);
 
    // TODO: ADD EDNS CLIENT

    unsigned int packet_len = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);

    printf("Sending %f data=%p len=%d client=%s mask=%u", current_time(), buf, packet_len, client, mask);

    hex_and_ascii_print("\r\n", buf, packet_len);
    printf("\n");

    struct sockaddr_in edns;
    memset(&edns,0,sizeof edns);  
    char str_client[40];
    strcpy(str_client, client);
    edns.sin_family = AF_INET;
    inet_aton(str_client, &edns.sin_addr);

    const char* edns_info = "\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x0b\x00\x08\x00\x07\x00\x01";
    memcpy(buf+packet_len, edns_info, 17);

    uint8_t edns_len = 22;
    // encode the client mask
    buf[packet_len+17] = mask;
    buf[packet_len+18] = 0;

    // encode the client address, could be a compressed address. Only handlng /24 and /32 properly
    buf[packet_len+19] = edns.sin_addr.s_addr & 0xFF; /* 0x18 */
    buf[packet_len+20] = (edns.sin_addr.s_addr & 0xFF00)>>8; /*0x3e;*/
    buf[packet_len+21] = (edns.sin_addr.s_addr & 0xFF0000)>>16; /*0xb9;*/
    if (mask == 32) {
	buf[packet_len+22] = (edns.sin_addr.s_addr & 0xFF000000)>>24; 
	edns_len++;
    }
    
    hex_and_ascii_print("\r\n", buf, packet_len+edns_len);
    printf("\n");

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(target);
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
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
    CFG.id[0] = 0;
    CFG.domain[0] = 0;
    CFG.domain_test[0] = 0;
    CFG.blackhole_ip[0] = 0;
    CFG.blackhole_as_refused = 0;
    CFG.redis = NULL;
    CFG.event_cache = (Pvoid_t) NULL;
    CFG.event_total = 0;
    CFG.event_count = 0;
    CFG.debug = 0;
    CFG.timer = 0;
    CFG.relay = 0;
    strcpy(CFG.event_channel, "beacon");

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
	log_debug("plugin_beacon: config id=%s ip=%s domain=%s domain_test=%s blackhole=%s blackhole_as_refused=%s",
		  CFG.id, CFG.ip, CFG.domain, CFG.domain_test, CFG.blackhole_ip, 
		  CFG.blackhole_as_refused ? "true":"false");
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
    uint8_t is_override = 0;
    uint8_t is_proxy = 0;
    // Determine if we've got an zone level answer for this resolution
    // beacon!IPV4 => give up the IPV4
    // beacon!proxy_IPV4 => give up the IPV4 and 
    if (PV != NULL) {
	result_ip =(char*)*PV;
	const char* proxy = "proxy_";
	char* res = strstr(proxy, result_ip);
	if (res == NULL) {
	    is_proxy = 1;
	    result_ip += 6;
	}
	is_override = 1;
    }

    // Deferred until iothread init (after potential daemonization)
    if (CFG.timer == 0) {
	pthread_create (&DNS_TELEMETRY_THREAD, NULL, &dyn_beacon_timer, NULL);
	log_info("plugin_beacon: background_timer initialized");
	CFG.timer = 1;
    }

    // printf("plugin_beacon_resolve\n");

    double network_time = current_time();
    u_int is_valid = 1;
    u_int is_test = 0;
    const u_char* qdata = cinfo->qname+1;
    u_char* qname = convert_qname(qdata);

    char temp[1024];
    strcpy(temp, (char*)qname);
    char* saveptr, *domain;
    char* cid = strtok_r(temp, ".", &saveptr);
    char* cdata = strtok_r(NULL, ".", &saveptr);
    char* beacon = strtok_r(NULL, ".", &saveptr);
    domain = saveptr;

    struct in_addr client, client_subnet_addr;
    client.s_addr = cinfo->dns_source.sin.sin_addr.s_addr; 
    char* s_client = inet_ntoa(client);
    char str_client[DMN_ANYSIN_MAXLEN+1];
    strcpy(str_client, s_client);


    char* proxy_client = str_client;
    char s_edns_client[DMN_ANYSIN_MAXLEN+1];
    client_subnet_addr.s_addr = cinfo->edns_client.sin.sin_addr.s_addr;
    char* s_edns = inet_ntoa(client_subnet_addr);
    uint8_t mask = 32;

    printf("s_client=%s\n", str_client);
    printf("s_edns=%s\n", s_edns);

    if (client_subnet_addr.s_addr == 0)
	strcpy(s_edns_client, "-");
    else {
	sprintf(s_edns_client, "%s/%d", s_edns, cinfo->edns_client_mask);
	mask = cinfo->edns_client_mask;
	// proxy_client = s_edns_client;
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

    printf("resolve %s resnum=%d => %s %s %s proxy=%s client=%s edns=%s\n", qname, resnum, result_ip, is_override?"(override)":"", is_proxy?"(proxy)":"", proxy_client, str_client, s_edns_client);

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
    
    // printf("..resnum=%u\ncid=%s\n..cdata=%s\n..beacon=%s\n..domain=%s\n..client=%s\n..edns_client=%s\n..is_valid=%d\n..is_test=%d\n..domain_test=%s\n", resnum,cid,cdata,beacon,domain,s_client, s_edns_client, is_valid, is_test, CFG.domain_test);

    if (is_valid) {
	// Don't publish beacon telemetry if it was for the test domain
	if (!is_test) {
	    pthread_mutex_lock(&DYN_BEACON_MUTEX); 
	    char* val = (char*)malloc(256);
	    sprintf(val, "%f,D,%s,%s,%s,%s,%s,%s", network_time,CFG.id,str_client, beacon, cid, cdata, s_edns_client);
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

	if (is_proxy) {
	    if (CFG.relay) {
		// ngethostbyname(str_client, 32, result_ip, qname, T_A);
		ngethostbyname(proxy_client, mask, result_ip, qname, T_A);
	    } else {
		printf("  NOT RELAYING to %s\n", proxy_client);
	    }
	}


   } else if (CFG.blackhole_as_refused) {
	// REFUSED. Possibly not very kosher. But sort of equivalent of simply dropping the request.
	((wire_dns_header_t*)cinfo->res_hdr)->flags2 = DNS_RCODE_REFUSED;
    } else {
	// Return blackhole IP with no error
	dmn_anysin_t tmpsin;
	gdnsd_anysin_fromstr(CFG.blackhole_ip, 0, &tmpsin);
	gdnsd_result_add_anysin(result, &tmpsin);
    }

    return 0; // GDNSD_STTL_TTL_MAX;
}

