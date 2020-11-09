/*
 * Copyright (c) 2014-2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL XEROX OR PARC BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ################################################################################
 * #
 * # PATENT NOTICE
 * #
 * # This software is distributed under the BSD 2-clause License (see LICENSE
 * # file).  This BSD License does not make any patent claims and as such, does
 * # not act as a patent grant.  The purpose of this section is for each contributor
 * # to define their intentions with respect to intellectual property.
 * #
 * # Each contributor to this source code is encouraged to state their patent
 * # claims and licensing mechanisms for any contributions made. At the end of
 * # this section contributors may each make their own statements.  Contributor's
 * # claims and grants only apply to the pieces (source code, programs, text,
 * # media, etc) that they have contributed directly to this software.
 * #
 * # There is no guarantee that this section is complete, up to date or accurate. It
 * # is up to the contributors to maintain their portion of this section and up to
 * # the user of the software to verify any claims herein.
 * #
 * # Do not remove this header notification.  The contents of this section must be
 * # present in all distributions of the software.  You may only modify your own
 * # intellectual property statements.  Please provide contact information.
 *
 * - Palo Alto Research Center, Inc
 * This software distribution does not grant any rights to patents owned by Palo
 * Alto Research Center, Inc (PARC). Rights to these patents are available via
 * various mechanisms. As of January 2016 PARC has committed to FRAND licensing any
 * intellectual property used by its contributions to this software. You may
 * contact PARC at cipo@parc.com for more information or visit http://www.ccnx.org
 */
/**
 * @author Glenn Scott, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2014-2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */
#include <config.h>
#include <LongBow/runtime.h>

#include <time.h>

#include <getopt.h>
#include <stdio.h>

#include "ccnxPortalServer_About.h"

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include <parc/algol/parc_Buffer.h>
#include <parc/algol/parc_BufferComposer.h>
#include <parc/algol/parc_Memory.h>
#include <parc/security/parc_Security.h>
#include <parc/security/parc_PublicKeySigner.h>
#include <parc/security/parc_IdentityFile.h>

#include <ccnx/common/ccnx_Name.h>

extern PARCBuffer *makePayload(const CCNxName *interestName, const char *commandString);
extern int ccnServe(const PARCIdentity *identity, const CCNxName *listenName, int port, const char *commandString, int mode);
extern void usage(void);

PARCBuffer *
makePayload(const CCNxName *interestName, const char *commandString)
{
    char *commandToExecute;

    char *nameAsString = ccnxName_ToString(interestName);

    PARCBufferComposer *accumulator = parcBufferComposer_Create();

    if(commandString == NULL) {
      /* use built in command  */
        parcBufferComposer_PutString(accumulator, "Built-in: ");
        parcBufferComposer_PutString(accumulator, nameAsString);
        parcBufferComposer_PutString(accumulator, "\n");
    } else {
      int failure = asprintf(&commandToExecute, commandString, nameAsString);
      assertTrue(failure > -1, "Error asprintf");

      parcMemory_Deallocate((void **) &nameAsString);
      
      FILE *fp = popen(commandToExecute, "r");
      if (fp != NULL) {
        unsigned char buffer[1024];
	
        while (feof(fp) == 0) {
	  size_t length = fread(buffer, sizeof(char), sizeof(buffer), fp);
	  parcBufferComposer_PutArray(accumulator, buffer, length);
        }
        pclose(fp);
      } else {
        parcBufferComposer_PutString(accumulator, "Cannot execute: ");
        parcBufferComposer_PutString(accumulator, commandString);
      }
    }

    PARCBuffer *payload = parcBufferComposer_ProduceBuffer(accumulator);
    parcBufferComposer_Release(&accumulator);
    return payload;
}

int
ccnServe(const PARCIdentity *identity, const CCNxName *listenName, int port, const char *commandString, int mode)
{
    char tcpConnectString[50];

    printf("Mode: %d\n", mode);

    
    snprintf(tcpConnectString, 50, "tcp://127.0.0.1:%d", port);
  
    parcSecurity_Init();

    CCNxPortalFactory *factory = ccnxPortalFactory_Create(identity);

    ccnxPortalFactory_SetProperty(factory, CCNxPortalFactory_LocalForwarder, tcpConnectString);

    CCNxPortal *portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
    assertNotNull(portal, "Expected a non-null CCNxPortal pointer.");

    if(mode == 1) {
      PARCBuffer *payload = makePayload(listenName, commandString);
      
      CCNxContentObject *contentObject = ccnxContentObject_CreateWithNameAndPayload(listenName, payload);
      ccnxContentObject_SetExpiryTime(contentObject, 1);
      ccnxContentObject_SetFinalChunkNumber(contentObject, /*const uint64_t* finalChunkNumber*/ 2);

      CCNxMetaMessage *message = ccnxMetaMessage_CreateFromContentObject(contentObject);
      
      if (ccnxPortal_Send(portal, message, CCNxStackTimeout_Never) == false) {
	fprintf(stderr, "Mode 1: ccnxPortal_Write failed: %d\n", ccnxPortal_GetError(portal));
      }
    }
    mode = 0;
    
    if(mode == 0) {
      if (ccnxPortal_Listen(portal, listenName, 365 * 86400, CCNxStackTimeout_Never)) {
	uint32_t entryCount;
	uint32_t exitCount;
        while (true) {
	  CCNxMetaMessage *request = ccnxPortal_Receive(portal, CCNxStackTimeout_Never);
	  //CCNxMetaMessage *request = ccnxPortal_Receive(portal, CCNxStackTimeout_Microseconds(3000000L); // 3 seconds
	  if (request == NULL) {
	    // Check errno for reason
	    printf("====> ccnx-server: ccnxPortal_Receive() Error code: %d\n", ccnxPortal_GetError(portal));
	    break;
	  }
	  
	  CCNxInterest *interest = ccnxMetaMessage_GetInterest(request);
	  
	  if (interest != NULL) {
	    // DEBUG
	    entryCount = parcBuffer_InstanceCount();
	    fprintf(stderr, ">>>>>> Interest Entry parcBuffer_InstanceCount(): %"PRIu32"\n", entryCount);

	    CCNxName *interestName = ccnxInterest_GetName(interest);
	    
	    char *name = ccnxName_ToString(interestName);
	    printf("Interest: %s\n", name);
	    parcMemory_Deallocate((void **) &name);
	    
	    
	    
	    PARCBuffer *payload = makePayload(interestName, commandString);
	    
	    CCNxContentObject *contentObject = ccnxContentObject_CreateWithNameAndPayload(interestName, payload);
	    
	    CCNxMetaMessage *message = ccnxMetaMessage_CreateFromContentObject(contentObject);
            
	    //jgo start testing
	    /*
	      OTOCnInterestParam *param = ccnxInterest_GetInterestParam(interest);
	      printf("printing out the interest Param\n");
              
	      if (param != NULL){
	      otocnInterestParam_Display(param, 10);
	      } else {
	      printf("No interest Param passed\n");
	      }
              
	      OTOCnProfileMetric *metric = ccnxInterest_GetProfileMetric(interest);
	      if (metric != NULL){
	      otocnProfileMetric_Display(metric, 10);
	      
	      struct timeval * tStamp = otocnProfileMetric_GetTimeStamp(metric, 2);
	      printf("initial timestamp is : %ld.%06ld\n", tStamp->tv_sec, tStamp->tv_usec);
              
	      } else {
	      printf("No interest ProfileMetric passed\n");
	      }
	    */
	    //end jgo testing
            
	    if (ccnxPortal_Send(portal, message, CCNxStackTimeout_Never) == false) {
	      fprintf(stderr, "ccnxPortal_Write failed: %d\n", ccnxPortal_GetError(portal));
	    }
	    
	    /*
	      if(0) {
	      char *name = ccnxName_ToString(interestName);
	      time_t theTime = time(0);
	      char *time = ctime(&theTime);
	      printf("%24.24s  %s\n", time, name);
	      parcMemory_Deallocate((void **) &name);
	      }
	    */
	    
	    parcBuffer_Release(&payload);
	    ccnxContentObject_Release(&contentObject);
	    ccnxMetaMessage_Release(&message);

	    exitCount = parcBuffer_InstanceCount();
	    fprintf(stderr, ">>>>>> Interest Exit parcBuffer_InstanceCount(): %"PRIu32"\n", exitCount);
	  }
	  ccnxMetaMessage_Release(&request);

	}
      }
    } /* bottom mode == 0 */

    ccnxPortal_Release(&portal);

    ccnxPortalFactory_Release(&factory);

    parcSecurity_Fini();

    return 0;
}

void
usage(void)
{
    printf("ccnx-server --identity <file> --password <password> lci:/ccn-name command-to-execute\n");
    printf("ccnx-server [-h | --help]\n");
    printf("ccnx-server [-v | --version]\n");
    printf("-P | --Port     = Port number to use for forwarder local connection, the default is 9695\n");
    printf("\n");
    printf("    --identity         The file name containing a PKCS12 keystore\n");
    printf("    --password         The password to unlock the keystore\n");
    printf("    lci:/ccn-name      The LCI name of the object fetch\n");
    printf("    program-to-execute The program to run (eg. /bin/date)\n");
}

int
main(int argc, char *argv[argc])
{
  char *keystoreFile = NULL;
  char *keystorePassword = NULL;
  char *commandString = NULL; /* "/bin/date"; */
  char *listenName = "lci:/Server";
  int port = 9695;
  int mode = 0;
  
  /* options descriptor */
  static struct option longopts[] = {
    { "identity", required_argument, NULL, 'f' },
    { "password", required_argument, NULL, 'p' },
    { "Port",     required_argument, 0, 'P' },
    { "mode",     required_argument, 0, 'm' },
    { "help",     no_argument,       NULL, 'h' },
    { "version",  no_argument,       NULL, 'v' },
    { NULL,       0,                 NULL, 0   }
  };
  
  if (argc < 2) {
    usage();
    exit(1);
  }
  
  int ch;
  while ((ch = getopt_long(argc, argv, "fphvc:", longopts, NULL)) != -1) {
    switch (ch) {
    case 'f':
      keystoreFile = optarg;
      break;
      
    case 'p':
      keystorePassword = optarg;
      break;
      
    case 'v':
      printf("%s\n", ccnxPortalServerAbout_Version());
      return 0;
      
    case 'h':
      usage();
      return 0;
      
    case 'P':
      sscanf(optarg, "%d", &port);
      if( (port < 1024) || (port > 32767) ) {
	fprintf(stderr, "Specified port number out of range: %d\n\n", port);
	usage();
	return 0;
      }
      break;
      
    case 'm':
      sscanf(optarg, "%d", &mode);
      break;
      
    default:
      usage();
      return -1;
    }
  }
  
  argc -= optind;
  argv += optind;
  
  printf("remaining argc = %d\n", argc);
  
  if (argc == 0 || argv[0] == NULL || keystoreFile == NULL || keystorePassword == NULL) {
    usage();
    return -1;
  }
  
  /* get listen name */
  listenName = argv[0];
  
  if(argc >= 1) {
    commandString = argv[1];
  }
  
  /*     argc += 2; */
  
  PARCIdentityFile *identityFile = parcIdentityFile_Create(keystoreFile, keystorePassword);
  
  if (parcIdentityFile_Exists(identityFile) == false) {
    printf("Inaccessible keystore file '%s'.\n", keystoreFile);
    exit(1);
  }
  
  PARCIdentity *identity = parcIdentity_Create(identityFile, PARCIdentityFileAsPARCIdentity);
  parcIdentityFile_Release(&identityFile);
  
  CCNxName *name = ccnxName_CreateFromCString(listenName);
  
  int result = ccnServe(identity, name, port, commandString, mode);
  
  ccnxName_Release(&name);
  
  return result;
}
