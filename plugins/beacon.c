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
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    CFG.redis = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if (CFG.redis == NULL || CFG.redis->err) {
	if (CFG.redis) {
	    log_debug("Connection error: %s\n", CFG.redis->errstr);
	    redisFree(CFG.redis);
	} else {
	    log_debug("Connection error: can't allocate redis context\n");
	}
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
	if (CFG.redis != NULL) {
	    Word_t delta = CFG.event_count - CFG.event_total;
	    CFG.event_total = CFG.event_count;

	    log_debug("%f beacon new=%u tot=%u", current_time(), (unsigned int)delta, (unsigned int)CFG.event_total);

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
			redisReply *reply = (redisReply*)redisCommand(CFG.redis, buffer);
			freeReplyObject(reply);
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
		redisReply *reply = (redisReply*)redisCommand(CFG.redis, buffer);
		freeReplyObject(reply);
	    }
	} else {
	    printf("TODO: HEARTBEAT re-establish REDIS channel\n");
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
    }
    return 1;
}

// -- END DYN BEACON IMPL ------------------------------------

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

    redis_init();
    // Create timer thread
    pthread_t thread;
    pthread_create (&thread, NULL, &dyn_beacon_timer, NULL);
}


int plugin_beacon_map_res(const char* resname V_UNUSED, const uint8_t* origin V_UNUSED) {
    return 0;
}

gdnsd_sttl_t plugin_beacon_resolve(unsigned resnum V_UNUSED, const uint8_t* origin V_UNUSED, const client_info_t* cinfo, dyn_result_t* result) {

    // printf("plugin_beacon_resolve\n");

    double network_time = current_time();
    u_int is_valid = 1;
    u_int is_test = 0;
    const u_char* qdata = cinfo->qname+1;
    u_char* qname = convert_qname(qdata);

    // printf("..qname=%s\n", qname);

    char temp[1024];
    strcpy(temp, (char*)qname);
    char* saveptr, *domain;
    char* cid = strtok_r(temp, ".", &saveptr);
    char* cdata = strtok_r(NULL, ".", &saveptr);
    char* beacon = strtok_r(NULL, ".", &saveptr);
    domain = saveptr;

    struct in_addr client, client_subnet_addr;
    client.s_addr = cinfo->dns_source.sin.sin_addr.s_addr; 
    const char* s_client = inet_ntoa(client);
    char s_edns_client[DMN_ANYSIN_MAXLEN+1];
    client_subnet_addr.s_addr = cinfo->edns_client.sin.sin_addr.s_addr;
    if (client_subnet_addr.s_addr == 0)
	strcpy(s_edns_client, "-");
    else {
	sprintf(s_edns_client, "%s/%d", s_client, cinfo->edns_client_mask);
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
    
    // printf("..cid=%s\n..cdata=%s\n..beacon=%s\n..domain=%s\n..client=%s\n..edns_client=%s\n..is_valid=%d\n..is_test=%d\n..domain_test=%s\n", cid,cdata,beacon,domain,s_client, s_edns_client, is_valid, is_test, CFG.domain_test);

    if (is_valid) {
	// Don't publish beacon telemetry if it was for the test domain
	if (!is_test) {
	    pthread_mutex_lock(&DYN_BEACON_MUTEX); 
	    char* val = (char*)malloc(256);
	    sprintf(val, "%f,D,%s,%s,%s,%s,%s,%s", network_time,CFG.id,s_client, beacon, cid, cdata, s_edns_client);
	    PWord_t PV = NULL;
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
	gdnsd_anysin_fromstr(CFG.ip, 0, &tmpsin);
	gdnsd_result_add_anysin(result, &tmpsin); 
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

