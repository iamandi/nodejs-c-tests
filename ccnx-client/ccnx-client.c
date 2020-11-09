
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

//jgo random number
#include <time.h>
#include <stdlib.h>
#include <ccnx/common/ccnx_NameSegment.h>
//end random number

#include <LongBow/runtime.h>

//#include "ccnxPortalClient_About.h"

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>
#include <parc/security/parc_PublicKeySigner.h>

#include <parc/algol/parc_Memory.h>

#include <parc/algol/parc_InputStream.h>
#include <parc/algol/parc_OutputStream.h>
#ifdef OTOCN
#include <otocn/otocn_InterestParam.h>
#endif

#if defined(WIN32) || defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

int
ccnGet(PARCIdentity *identity, CCNxName *name)
{
    CCNxPortalFactory *factory = ccnxPortalFactory_Create(identity);

    CCNxPortal *portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);

    assertNotNull(portal, "Expected a non-null CCNxPortal pointer.");

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
//    CCNxInterest *interest = ccnxInterest_Create(name, 0, NULL, paramObj, pmetric, NULL);
    res = ccnxInterest_SetInterestParam(interest, paramObj);
    if(res == false) {
        printf("SET Interest with OTOCNInterestParam is FALSE\n");
        otocnInterestParam_Release(&paramObj);        
        ccnxPortalFactory_Release(&factory);
        parcBuffer_Release(&key);
        ccnxName_Release(&name);
        ccnxPortal_Release(&portal);
        parcBuffer_Release(&signature);
        parcBuffer_Release(&certification);
        otocnProfileMetric_Release(&pmetric);
        exit(0);
    } else {
        res = ccnxInterest_SetProfileMetric(interest, pmetric);
        if (res == false) {
            printf("SET Interest with OTOCNProfileMetric is FALSE\n");
            otocnProfileMetric_Release(&pmetric);
            otocnInterestParam_Release(&paramObj);        
            ccnxPortalFactory_Release(&factory);
            parcBuffer_Release(&key);
            ccnxName_Release(&name);
            ccnxPortal_Release(&portal);
            parcBuffer_Release(&signature);
            parcBuffer_Release(&certification);
            otocnProfileMetric_Release(&pmetric);
            exit(0);
        }
    }
 //end jgo testing
#else
    CCNxInterest *interest = ccnxInterest_CreateSimple(name);
#endif
    ccnxName_Release(&name);

    CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);
    if (ccnxPortal_Send(portal, message, CCNxStackTimeout_Never)) {
        while (ccnxPortal_IsError(portal) == false) {
            CCNxMetaMessage *response = ccnxPortal_Receive(portal, CCNxStackTimeout_Never);
            if (response != NULL) {
                if (ccnxMetaMessage_IsContentObject(response)) {
                    CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);
		    if(ccnxContentObject_HasFinalChunkNumber(contentObject)) {
		      // uint64_t ccnxContentObject_GetFinalChunkNumber(const CCNxContentObject *contentObject)
		      printf("finalChunkNumber: %lu\n", ccnxContentObject_GetFinalChunkNumber(contentObject));
		    }
		    
                    PARCBuffer *payload = ccnxContentObject_GetPayload(contentObject);

                    size_t length = parcBuffer_Remaining(payload);
                    ssize_t nwritten = write(1, parcBuffer_Overlay(payload, length), length);
                    assertTrue(nwritten == length, "Did not write whole buffer, got %zd expected %zu", nwritten, length);

                    break;
                }
                ccnxMetaMessage_Release(&response);
            }
        }
    }

    ccnxPortal_Release(&portal);

    ccnxPortalFactory_Release(&factory);
#ifdef OTOCN
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
    printf("ccn-client --identity <file> --password <password> <objectName>\n");
    printf("ccn-client [-h | --help]\n");
    printf("ccn-client [-v | --version]\n");
    printf("\n");
    printf("    --identity  The file name containing a PKCS12 keystore\n");
    printf("    --password  The password to unlock the keystore\n");
    printf("    <objectName> The LCI name of the object to fetch\n");
}

EXPORT int
//main(int argc, char *argv[argc])
ccnxClient(char* keystoreFileArg, char* keystorePasswordArg, char* ccnxName)
{
    char *keystoreFile = keystoreFileArg;
    char *keystorePassword = keystorePasswordArg;


    char *objectName = ccnxName;

    PARCIdentityFile *identityFile = parcIdentityFile_Create(keystoreFile, keystorePassword);
    if (parcIdentityFile_Exists(identityFile) == false) {
        printf("Inaccessible keystore file '%s'.\n", keystoreFile);
        exit(1);
    }


    PARCIdentity *identity = parcIdentity_Create(identityFile, PARCIdentityFileAsPARCIdentity);
    if(identity == NULL) {
      printf("parcIdentity_Create() returned NULL, exit\n");
	exit(1);
    }
    
    parcIdentityFile_Release(&identityFile);
    
    CCNxName *name = ccnxName_CreateFromCString(objectName);
    int result = 0 ;
    result = ccnGet(identity, name);
    ccnxName_Release(&name);

    parcIdentity_Release(&identity);

    return result;
}
