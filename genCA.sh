#!/bin/sh

#openssl genrsa -out rsa_private.key 2048
#openssl rsa -in rsa_private.key -pubout -out rsa_public.key

if [ $# -lt 1 ];then
echo "usage：\n\t$0 dir\n"
exit 0
fi

if [ ! -d $1 ];then
mkdir -p $1/client
mkdir -p $1/server
else 
mkdir -p $1/client
mkdir -p $1/server
fi

openssl req -newkey rsa:2048 -nodes -keyout $1/client/rsa_private.key -x509 -days 3650 -out $1/client/client.crt -subj "/C=CN/ST=HB/L=WUHAN/O=BIGTMT/OU=Client/CN=bigtmt.com/emailAddress=xxx@bigtmt.com"
openssl req -newkey rsa:2048 -nodes -keyout $1/server/rsa_private.key -x509 -days 3650 -out $1/server/server.crt -subj "/C=CN/ST=HB/L=WUHAN/O=BIGTMT/OU=Server/CN=bigtmt.com/emailAddress=xxx@bigtmt.com"

# openssl x509 -req -days 3650 -in $1/client/client.csr -signkey $1/client/rsa_private.key -out $1/client/client.crt
# openssl x509 -req -days 3650 -in $1/server/server.csr -signkey $1/server/rsa_private.key -out $1/server/server.crt
# openssl rsa -in rsa_private.key -noout -text
# openssl x509 -noout -text -in cert.crt