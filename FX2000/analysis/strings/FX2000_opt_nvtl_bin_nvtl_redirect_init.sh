#!/bin/sh
# script used to pull out the friendly url from hosts file and use it for the redirect rule 
cat /etc/hosts | awk '
	if(NR == 1)	{
		printf("var.lan_ip = \"%s\"\n",$1); 
		printf("var.friendlyUrl = \"%s\"\nvar.excludeList = \"%s$|%s$",$2,$2,$1);
	} else if(NR == 2) {
		printf("|%s$|%s$",$2,$1);
	} else { 
		printf("|%s$",$2);
	printf("\"\n");
