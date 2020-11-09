# CCNx compilation commands

/usr/bin/cc -DOTOCN=1 -DRELEASE_VERSION=\"1.0.20170209.e86cb442\" -I/home/otocn/CCNx_Distillery/usr/include -I/./home/otocn/CCNx_Distillery/usr/include -fPIC -Wall -std=gnu99 -o ./ccnx-client.c.o -c ./ccnx-client.c

/usr/bin/cc -fPIC -fpic -Wall -g -shared -rdynamic ./ccnx-client.c.o -o libccnx_client.so -Wl,-rpath,/home/otocn/CCNx_Distillery/usr/lib: -lm /home/otocn/CCNx_Distillery/usr/lib/liblongbow.so /home/otocn/CCNx_Distillery/usr/lib/liblongbow-textplain.so -lssl -lcrypto -lpthread /home/otocn/CCNx_Distillery/usr/lib/libccnx_api_portal.so /home/otocn/CCNx_Distillery/usr/lib/libccnx_transport_rta.so /home/otocn/CCNx_Distillery/usr/lib/libccnx_api_control.so /home/otocn/CCNx_Distillery/usr/lib/libccnx_api_notify.so /home/otocn/CCNx_Distillery/usr/lib/libccnx_common.so /home/otocn/CCNx_Distillery/usr/lib/libotocn.so /home/otocn/CCNx_Distillery/usr/lib/libparc.so -lm

1. Delete .so and .o files.
2. Compile ccnx-client using above commands
3. Start forwarder and ccnx-server -> ./usr/bin/ccnx-server --identity key-store/keystoreserver.otocn --password 123321 lci:/ccn-name /bin/date
4. node ccnx-client.js
