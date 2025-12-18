#!/bin/sh
# script used to pull out the any fastcgi configurations
SYSSER_FCGI_CONF_PATH=/etc/lighttpd/conf.d/sysserfastcgi.conf
RESTAPI_FCGI_CONF_PATH=/etc/lighttpd/conf.d/restapifastcgi.conf
if [ -e $SYSSER_FCGI_CONF_PATH ] ; then
	cat $SYSSER_FCGI_CONF_PATH
if [ -e $RESTAPI_FCGI_CONF_PATH ] ; then
	cat $RESTAPI_FCGI_CONF_PATH
