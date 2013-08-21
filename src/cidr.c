/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "cidr.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "../lib/logger.h"
#include "../lib/blacklist.h"

#include "state.h"
#include "aesrand.h"


static uint32_t current = 0;
static uint32_t last = 0;
static char** cidrs;
static uint32_t cidrs_position = 0;

int cidr_init(char* conf_cidr)
{

	cidrs = cidr_split(conf_cidr, ",");

	log_info("cidr", "CIDRs to scan:");
    for (int x = 0; cidrs[x] != NULL ; x++)
    {
    	log_info("cidr", "%s", cidrs[x]);
    }
	

    process_cidr(cidrs[cidrs_position]);
	

// uint8_t octet[4];
 //    int x;
 //    for (x = 0; x < 4; x++)
 //    {
 //        octet[x] = (first >> (x * 8)) & (uint8_t)-1;
 //    }
	// log_info("send"," First IP %d.%d.%d.%d", octet[3],octet[2],octet[1],octet[0]);

 //    for (x = 0; x < 4; x++)
 //    {
 //        octet[x] = (last >> (x * 8)) & (uint8_t)-1;
 //    }
	// log_info("send"," Last IP %d.%d.%d.%d", octet[3],octet[2],octet[1],octet[0]);

	//Convert to same format that will be used in the packet send.


	// uint32_t val = current_;
	// val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
	// current = (val << 16) | (val >> 16);
	

	return 0;
}

uint32_t cidr_get_next_ip(void)
{
	// printf("cidr_get_next_ip!!\n");
	uint32_t val = 0;
	// if(current == 0){
	// 	// printf("current %d\n", current);
	// 	current = zsend.first_scanned;
	// 	val = current;
	// 	val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
	// 	val = (val << 16) | (val >> 16);

	// }

	if(current > last){
		// printf("Im at last for this cidr..\n\n");
		// printf("curr %d\n", current);
		// printf("last %d\n", last);
		log_info("cidr", "Got to the last of this cidr %d", cidrs_position);
		cidrs_position += 1;
		if(cidrs[cidrs_position] != '\0'){

			log_info("cidr", "Going to CIDR %s", cidrs[cidrs_position]);
			process_cidr(cidrs[cidrs_position]);

			
			// printf("NEW curr %d\n", current);
			// printf("NEW last %d\n", last);

			// printf("zsend.last_to_scan %d\n", zsend.last_to_scan);
			// printf("Next is %d\n\n", current);
			val = current++;
			val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
			val = (val << 16) | (val >> 16);


			if(cidrs[cidrs_position+1] == '\0'){
				zsend.last_to_scan = 1;
				log_info("cidr", "Done all cidrs!");
				// val = current;
				// val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
				// val = (val << 16) | (val >> 16);
				// return val;
			}
		}
	}
	else{
		val = current++;
		// printf("Next is %d\n\n", val);
		val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
		val = (val << 16) | (val >> 16);
	}
	

	// 	printf("get candidate");
	// 	uint32_t candidate  = current++;
	// 	if (!blacklist_is_allowed(candidate)) {
	// 		zsend.blacklisted++;
	// 	} else {
	// 		return candidate;
	// 	}
	// }

	return val;
}

int process_cidr(char* cidr_)
{


    // log_info("XXXXXXXXXXXXX", "%s", cidr_);

	char* cidr = malloc (1 + strlen (cidr_));
	memcpy(cidr, cidr_, strlen(cidr_)+1);


    // log_info("XXXXXXXXXXXXX", "%s", cidr);
    

	log_info("cidr", "Processing next cidr %s", cidr);
	//Split the range and IP
	char** range_split = cidr_split(cidr, "/");
	char* range = range_split[1];
	//Get IP split
	char** split = cidr_split(range_split[0], ".");

	//Get start of CIDR
	uint32_t first = (unsigned long) (atoll(split[0]) * 16777216) + (atoll(split[1]) * 65536) + (atoll(split[2]) * 256) + atoll(split[3]);
	zsend.first_scanned = first;

	//Get end of CIDR
	int number_of_ips = (pow(2,(32-atoll(range))) - 1);
	uint32_t _last = (unsigned long) first + number_of_ips;

	uint32_t val = ((last << 8) & 0xFF00FF00 ) | ((last >> 8) & 0xFF00FF ); 
	val = (val << 16) | (val >> 16);
	
	last = _last;
	current = zsend.first_scanned;

	// printf("Scanning CIDR %s", cidr);
	// log_info("cidr", "Scanning CIDR %s", cidr);

	return 0;
}

uint32_t cidr_get_curr_ip(void)
{
	uint32_t val = current;
	val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
	return  (val << 16) | (val >> 16);
}

//Split CIDR
char** cidr_split(char* a_str, const char* s)
{
	char ** res  = NULL;
	char *  p    = strtok (a_str, s);
	int n_spaces = 0;


	/* split string and append tokens to 'res' */

	while (p) {
	  res = realloc (res, sizeof (char*) * ++n_spaces);

	  if (res == NULL)
	    exit (-1); /* memory allocation failed */

	  res[n_spaces-1] = p;

	  p = strtok (NULL, s);
	}


	/* realloc one extra element for the last NULL */

	res = realloc (res, sizeof (char*) * (n_spaces+1));
	res[n_spaces] = 0;


	return res;
}