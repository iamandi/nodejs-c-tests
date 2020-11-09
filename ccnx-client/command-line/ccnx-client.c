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

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

//jgo random number
#include <time.h>
#include <stdlib.h>
#include <ccnx/common/ccnx_NameSegment.h>
//end random number

#include <LongBow/runtime.h>

#include "ccnxPortalClient_About.h"

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
		      printf("finalChunkNumber: %u\n", ccnxContentObject_GetFinalChunkNumber(contentObject));
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
    printf("%s\n", ccnxPortalClientAbout_About());
    printf("ccn-client --identity <file> --password <password> <objectName>\n");
    printf("ccn-client [-h | --help]\n");
    printf("ccn-client [-v | --version]\n");
    printf("\n");
    printf("    --identity  The file name containing a PKCS12 keystore\n");
    printf("    --password  The password to unlock the keystore\n");
    printf("    <objectName> The LCI name of the object to fetch\n");
}

int
main(int argc, char *argv[argc])
{
    char *keystoreFile = NULL;
    char *keystorePassword = NULL;

    /* options descriptor */
    static struct option longopts[] = {
        { "identity", required_argument, NULL, 'f' },
        { "password", required_argument, NULL, 'p' },
        { "version",  no_argument,       NULL, 'v' },
        { "help",     no_argument,       NULL, 'h' },
        { NULL,       0,                 NULL, 0   }
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "fpthv", longopts, NULL)) != -1) {
        switch (ch) {
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

    /**************
     * BREAKS - multiple calls to portal creation corrupts memory !!!
     *
    //jgo testing by adding random number
    int32_t n = 999999;
    //time_t t;
    //srand((unsigned int)time(&t));
    
    int result = 0 ;
    int32_t min_num = 1000000;
    int32_t max_num = 9999999;
    int length = 7;
    char* str = malloc( length + 1 );
    int32_t r;
    for (int32_t i = min_num; i < n; i++) {
        //r = min_num + (rand() % (max_num - min_num));
        snprintf( str, length + 1, "%d", i );

        // PARCBuffer *value = parcBuffer_WrapCString(str);
        // CCNxNameSegment *segment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_NAME, value);
        CCNxName *name = ccnxName_CreateFromCString(objectName);
        // name = ccnxName_Append(name, segment);

        result = ccnGet(identity, name);
        ccnxName_Release(&name);
        printf("the %d th line", i);//jgo testing

        // parcBuffer_Release(&value);
        // ccnxNameSegment_Release(&segment);
    }
    
    parcMemory_Deallocate((void **) &str);
    ************/
    
    parcIdentity_Release(&identity);

    return result;
}
