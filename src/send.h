/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef _SEND_H
#define _SEND_H

int send_init(void);
int send_run(void);
char** cidr_split(char*, const char*);
char** cidr_range(char*);

#endif //_SEND_H
