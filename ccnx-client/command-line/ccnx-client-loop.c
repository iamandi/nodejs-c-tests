#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include <LongBow/runtime.h>

#include "ccnxPortalClient_About.h"

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>
#include <parc/security/parc_PublicKeySigner.h>

#include <parc/algol/parc_Memory.h>

#include <sys/time.h>
#include <parc/algol/parc_Time.h>

#include <parc/algol/parc_InputStream.h>
#include <parc/algol/parc_OutputStream.h>
#ifdef OTOCN
#include <otocn/otocn_InterestParam.h>
#include <ccnx/common/ccnx_NameSegment.h>
#endif
#include <unistd.h>


struct metis_forwarder;
typedef struct metis_forwarder MetisForwarder;
extern uint64_t metisForwarder_GetTicks(const MetisForwarder *metis);



//#define OTOCN_OFF 1

int
ccnGet(CCNxPortal *portal, CCNxName *name, bool floodFlag)
{
#ifdef OTOCN
    CCNxInterest *interest = ccnxInterest_CreateSimple(name, NULL, NULL);
    //jgo start testing
    PARCBuffer *key = parcBuffer_Allocate(8); //jgo testing
    parcBuffer_PutUint64(key, 1234L);//jgo testing
    parcBuffer_Flip(key);//jgo testing

    OTOCnInterestParam *paramObj = otocnInterestParam_CreateWithParam(key);

    PARCBuffer *signature = parcBuffer_AllocateCString("84232034bfa688280d7685d9fbbe642767634ad6472ff73c342ec4258157fa3a");
    PARCBuffer *certification = parcBuffer_AllocateCString("6508c916c790cf734a1d45e02b0d9a9e75674f6dab1ca02d1dfd79cf9585d613");
    OTOCnProfileMetric *pmetric = otocnProfileMetric_CreateWithParam(signature, certification);
    
    bool res = false;
    res = ccnxInterest_SetInterestParam(interest, paramObj);
    if(res == false) {
#ifdef DEBUG_DISPLAY
        printf("SET Interest with OTOCNInterestParam is FALSE\n");
#endif
        otocnInterestParam_Release(&paramObj);        
        parcBuffer_Release(&key);
        ccnxName_Release(&name);
        parcBuffer_Release(&signature);
        parcBuffer_Release(&certification);
        otocnProfileMetric_Release(&pmetric);
        exit(0);
    }

    res = ccnxInterest_SetProfileMetric(interest, pmetric);
    if (res == false) {
      printf("SET Interest with OTOCNProfileMetric is FALSE\n");
      otocnProfileMetric_Release(&pmetric);
      otocnInterestParam_Release(&paramObj);        
      parcBuffer_Release(&key);
      ccnxName_Release(&name);
      parcBuffer_Release(&signature);
      parcBuffer_Release(&certification);
      otocnProfileMetric_Release(&pmetric);
      exit(0);
    }
    //end jgo testing
#else
    CCNxInterest *interest = ccnxInterest_CreateSimple(name);
#endif

    char *stringName = NULL;
    CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);

    uint64_t startTime = parcTime_NowMicroseconds();
    // struct timeval parcTime_NowTimeval(void);
    // struct timeval parcTime_TimevalSubtract(const struct timeval *minuend, const struct timeval *subtrahend);

    /*
      #include <sys/time.h>
      #include <parc/algol/parc_Time.h>
      struct timeval {
      time_t         tv_sec      seconds // time_t is a int64
      suseconds_t    tv_usec     microseconds //suseconds_ is a int32
      };

      struct timeval parcTime_NowTimeval(void);
      struct timeval parcTime_TimevalSubtract(const struct timeval *minuend, const struct timeval *subtrahend);
      uint64_t parcTime_NowNanoseconds(void);
    */

    if (ccnxPortal_Send(portal, message, CCNxStackTimeout_Never)) {
      while ((ccnxPortal_IsError(portal) == false) && !floodFlag) {
	// CCNxMetaMessage *response = ccnxPortal_Receive(portal, CCNxStackTimeout_Never);
	CCNxMetaMessage *response = ccnxPortal_Receive(portal, CCNxStackTimeout_MicroSeconds(3000000L)); // 3 seconds
	if (response != NULL) {
	  if (ccnxMetaMessage_IsContentObject(response)) {
	    uint64_t finishTime = parcTime_NowMicroseconds();
	    
	    CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);
	    
	    PARCBuffer *payload = ccnxContentObject_GetPayload(contentObject);
	    size_t length = parcBuffer_Remaining(payload);
	    char *payloadString = (char *) parcBuffer_Overlay(payload, length);
	    stringName = ccnxName_ToString(name);

	    fprintf(stdout, "Name: %s, Start Time: %lu, Response time: %lu milliseconds, Payload: %.*s\n",
		    stringName,
		    startTime/1000L,
		    (finishTime - startTime)/1000L, length, payloadString);
	    //parcBuffer_Release(&payload);
	    ccnxMetaMessage_Release(&response);
	    break;
	  }
	  
	  // Not a ContentObject
	  if(ccnxMetaMessage_IsInterestReturn(response)) {
	    printf("====> ccnx-client-loop: ccnxPortal_Receive() InterestReturn message ignored...\n");
	  }
	  else if(ccnxMetaMessage_IsInterest(response)) {
	    printf("====> ccnx-client-loop: ccnxPortal_Receive() Interest message ignored...\n");
	  }
	  else if(ccnxMetaMessage_IsControl(response)) {
	    printf("====> ccnx-client-loop: ccnxPortal_Receive() Control message ignored...\n");
	  }
	  
	  // try for next message
	  ccnxMetaMessage_Release(&response);
	  continue;
	} else {
	  // Check errno for reason
	  printf("====> ccnx-client-loop: ccnxPortal_Receive() Error code: %d\n", ccnxPortal_GetError(portal));
	}
	
	  
      }
      
    } // bottom of while()

    if (stringName != NULL) parcMemory_Deallocate(&stringName);
    ccnxName_Release(&name);
    ccnxMetaMessage_Release(&message);
    ccnxInterest_Release(&interest);

#ifdef OTOCN_OFF
    parcBuffer_Release(&key);
    otocnInterestParam_Release(&paramObj);
    parcBuffer_Release(&signature);
    parcBuffer_Release(&certification);
    otocnProfileMetric_Release(&pmetric);
#endif
    return 0;
}

void
usage(void)
{
    printf("%s\n", ccnxPortalClientAbout_About());
    printf("ccn-client --identity <file> --password <password> <objectName> <delay>\n");
    printf("-P | --Port     = Port number to use for forwarder local connection, the default is 9695\n");
    printf("-x | --prefix   = character string to prefix the nuonce number\n");
    printf("ccn-client [-h | --help]\n");
    printf("ccn-client [-v | --version]\n");
    printf("\n");
    printf("    --identity  The file name containing a PKCS12 keystore\n");
    printf("    --password  The password to unlock the keystore\n");
    printf("    <objectName> The LCI name of the object to fetch\n");
    printf("    <delay> The delay between each interest, if not provided deafult is 0\n");   
}

int
main(int argc, char *argv[argc])
{
  char *nuoncePrefix = NULL;
    char *keystoreFile = NULL;
    char *keystorePassword = NULL;
    int port = 9695;
    bool floodFlag = false;
    
    /* options descriptor */
    static struct option longopts[] = {
        { "identity", required_argument, NULL, 'f' },
        { "password", required_argument, NULL, 'p' },
        { "version",  no_argument,       NULL, 'v' },
        { "flood",     no_argument,      NULL, 'F' },
        { "help",     no_argument,       NULL, 'h' },
        { "Port",     required_argument, 0, 'P' },
        { "prefix",   required_argument, NULL, 'x' },
        { NULL,       0,                 NULL, 0   }
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "fphv", longopts, NULL)) != -1) {
        switch (ch) {
            case 'x':
                nuoncePrefix = optarg;
                break;

            case 'f':
                keystoreFile = optarg;
                break;

            case 'p':
                keystorePassword = optarg;
                break;

            case 'v':
                printf("%s\n", ccnxPortalClientAbout_Version());
                return 0;

            case 'h':
                usage();
                return 0;

            case 'F':
	      floodFlag = true;
	      break;

	case 'P':
	  sscanf(optarg, "%d", &port);
	  if( (port < 1024) || (port > 32767) ) {
	    fprintf(stderr, "Specified port number out of range: %d\n\n", port);
	    usage();
	    return 0;
	  }
	  break;
		
            default:
                usage();
                return -1;
        }
    }

    argc -= optind;
    argv += optind;
    if (argv[0] == NULL || keystoreFile == NULL || keystorePassword == NULL) {
        usage();
        return -1;
    }

    char *objectName = argv[0];
    int delay  __attribute__((unused)) ;
    if (argv[1] != NULL) {
        delay = atoi(argv[1]);
    } else {
        delay = 0;
    }

    char tcpConnectString[50];
    
    snprintf(tcpConnectString, 50, "tcp://127.0.0.1:%d", port);
    
    PARCIdentityFile *identityFile = parcIdentityFile_Create(keystoreFile, keystorePassword);
    if (parcIdentityFile_Exists(identityFile) == false) {
        printf("Inaccessible keystore file '%s'.\n", keystoreFile);
        exit(1);
    }
    PARCIdentity *identity = parcIdentity_Create(identityFile, PARCIdentityFileAsPARCIdentity);
    parcIdentityFile_Release(&identityFile);


    // CCNxPortalFactory *factory = ccnxPortalFactory_Create(identity);
    CCNxPortalFactory *factory = ccnxPortalFactory_Create(NULL);

    ccnxPortalFactory_SetProperty(factory, CCNxPortalFactory_LocalForwarder, tcpConnectString);

    CCNxPortal *portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);

    assertNotNull(portal, "Expected a non-null CCNxPortal pointer.");

    ccnxPortalFactory_Release(&factory);

    int count = 0;
    //char cArray[10] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
    CCNxName *name = NULL;
    char str[20];

    int result = -1;
    do {
        name = ccnxName_CreateFromCString(objectName); 

        PARCBuffer *buf = NULL;
        snprintf(str, 20, "%s%d", nuoncePrefix, count);
        //printf("===> str = %s\n", str);

        //buf = parcBuffer_WrapCString(&cArray[count]);
        buf = parcBuffer_WrapCString(&str[0]);
        if(!parcBuffer_IsValid(buf)) {
            printf(">>>> buf is not valid");
            break;
        }

        CCNxNameSegment *segment = NULL;
        segment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_NAME, buf);
        if(!ccnxNameSegment_IsValid(segment)) {
            printf(">>>> segment is not valid");
            parcBuffer_Release(&buf);
            break;
        }

        CCNxName *appendedName = NULL;
        appendedName = ccnxName_Append(name, segment);
        if(!ccnxName_IsValid(appendedName)) {
            printf(">>>> appendedName is not valid");
            ccnxNameSegment_Release(&segment);
            parcBuffer_Release(&buf);
            break;
        }

        result = ccnGet(portal, appendedName, floodFlag);
       
        ccnxNameSegment_Release(&segment);
        parcBuffer_Release(&buf);
	
        count += 1;
        // sleep(delay);
        // printf("===> count = %d\n", count);
    } while ((result == 0) /*&& (count < 100)*/);

    ccnxPortal_Release(&portal);
    parcIdentity_Release(&identity);

    return result;
}
