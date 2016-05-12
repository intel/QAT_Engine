/* ====================================================================
 *
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2016 Intel Corporation.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 * ====================================================================
 */

#include "qat_parseconf.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include "qat_utils.h"
/*==========================================================*/
static char *confRemoveChar(char *inputStr, const char *charToRemove)
{
    char *endStr = NULL;
    char *startStr = inputStr;

    if (NULL == startStr || strlen(startStr) < 1) {
        return startStr;
    }

    while (*startStr && (strncmp(startStr, charToRemove, 1) == 0)) {
        startStr++;
    }

    if (strlen(startStr) < 1)
        return startStr;

    endStr = (char *)(startStr + (strlen(startStr) - 1));

    while (*endStr && (strncmp(endStr, charToRemove, 1) == 0)) {
        *endStr = '\0';
        endStr--;
    }
    return startStr;
}

/*==========================================================*/
static char *confRemoveWhiteSpace(char *inputStr)
{
    return confRemoveChar(inputStr, " ");
}

/*==========================================================*/
static char *confRemoveDoubleQuotes(char *inputStr)
{
    return confRemoveChar(inputStr, "\"");
}

/*==========================================================*/
static char *confRemoveStartingSquareBracket(char *inputStr)
{
    return confRemoveChar(inputStr, "[");
}

/*==========================================================*/
static int confRemoveEndSquareBracket(char *inputStr)
{
    char *scannedInputStr = NULL;
    if (NULL == inputStr)
        return 0;

    scannedInputStr = strchr(inputStr, ']');
    if (NULL == scannedInputStr) {
        return 0;
    } else {
        *scannedInputStr = '\0';
    }
    return 1;
}

/*==========================================================*/
static int confIsLineASectionName(char *inputStr)
{
    /*
     * Assumption: line has been stripped of leading/trailing white space
     * already
     */
    if (NULL == inputStr)
        return 0;

    if (strncmp(inputStr, "[", 1) == 0) {
        if (strchr(inputStr, ']') != NULL) {;
            return 1;
        }
    }

    return 0;
}

/*==========================================================*/
static int confParseSectionName(char *inputStr, char *sectionName)
{
    /*
     * Assumption: line has been stripped of leading/trailing whitespace
     * already
     */
    /*
     * Assumption: It has already been determined that the input string is a
     * Section Name by calling: confIsLineASectionName
     */
    char *strippedInputStr = confRemoveStartingSquareBracket(inputStr);

    if (!confRemoveEndSquareBracket(strippedInputStr))
        return 0;

    if (NULL == strippedInputStr)
        return 0;

    if (strncmp(sectionName, strippedInputStr, strlen(sectionName)) == 0) {
        return 1;
    }

    return 0;
}

/*==========================================================*/
static int confParseParameter(char *inputStr, char *keyName,
                              char *keyValue, size_t keyValueSize)
{
    char tempKeyName[CONF_MAX_LINE_LENGTH] = { 0 };
    char tempKeyValue[CONF_MAX_LINE_LENGTH] = { 0 };
    char *strippedKeyName = NULL;
    char *strippedKeyValue = NULL;
    char *doubleQuoteStrippedKeyValue = NULL;
    int tempKeyNameLen = 0;
    int tempKeyValueLen = 0;

    /* Check input parameters */
    if (NULL == inputStr)
        return 0;

    if ((strlen(keyName) > (CONF_MAX_LINE_LENGTH - 1)) ||
        (strlen(inputStr) > (CONF_MAX_LINE_LENGTH - 1)))
        return 0;

    /*
     * Separate the key name and value pair using the same method as the ia
     * driver does for consistency
     */
    if (sscanf(inputStr, "%[^=] = %[^#\n]", tempKeyName, tempKeyValue) !=
        CONF_PARAM_EXP_NUM_ARGS) {
        return 0;
    }

    /*
     * Check the strings are not too long - they should not be as we checked
     * inputStr earlier
     */
    tempKeyNameLen = strlen(tempKeyName);
    tempKeyValueLen = strlen(tempKeyValue);
    if ((tempKeyNameLen > (CONF_MAX_LINE_LENGTH - 1)) ||
        (tempKeyValueLen > (CONF_MAX_LINE_LENGTH - 1)))
        return 0;

    /* Strip whitespace and quotes as appropriate */
    strippedKeyName = confRemoveWhiteSpace(tempKeyName);
    strippedKeyValue = confRemoveWhiteSpace(tempKeyValue);
    doubleQuoteStrippedKeyValue = confRemoveDoubleQuotes(strippedKeyValue);

    if (NULL == strippedKeyName || NULL == doubleQuoteStrippedKeyValue)
        return 0;

    if (strncmp(keyName, strippedKeyName, strlen(keyName)) != 0)
        return 0;

    if (keyValueSize < strlen(doubleQuoteStrippedKeyValue))
        return 0;

    strncpy(keyValue, doubleQuoteStrippedKeyValue,
            strlen(doubleQuoteStrippedKeyValue));
    return 1;
}

/*==========================================================*/
int confCryptoFindKeyValue(char *fileName,
                           char *sectionName, char *keyName,
                           char *keyValue, size_t keyValueSize)
{
    FILE *conffile;
    int inSection = 0;
    int found = 0;
    int sectionFound = 0;
    char lineBuffer[CONF_MAX_LINE_LENGTH] = { 0 };
    int lineBufferLength = 0;
    char *strippedLineBuffer = NULL;

    if (strlen(fileName) > CONF_MAX_PATH) {
        fprintf(stderr, "Invaid Configuration File Name Length\n");
        return 0;
    }
    if ((conffile = fopen(fileName, "r")) != NULL) {
        while (!feof(conffile)) {
            if (fgets(lineBuffer, CONF_MAX_LINE_LENGTH, conffile) != NULL) {
                lineBufferLength = strlen(lineBuffer);
                if (lineBufferLength > 0) {

                    /*
                     * Remove any leading or trailing whitespace before
                     * trying to process further. It is okay to pass a NULL
                     * string to the confRemoveWhiteSpace function
                     */
                    strippedLineBuffer = confRemoveWhiteSpace(lineBuffer);

                    /*
                     * We didn't get a valid line, lets continue to next line
                     */
                    if (NULL == strippedLineBuffer)
                        continue;

                    /*
                     * We got a comment or empty line, ignore and continue to
                     * next line
                     */
                    if (('#' == *strippedLineBuffer)
                        || (0 == *strippedLineBuffer))
                        continue;

                    /* Check whether line is a section name */
                    if (confIsLineASectionName(strippedLineBuffer)) {
                        /* Are we already in the desired section? */
                        if (inSection) {
                            /*
                             * We are so we must have finished that section
                             * lets the flag so do not continue to process
                             * parameters within other sections
                             */
                            inSection = 0;
                        } else {
                            /*
                             * We aren't in the section already lets check
                             * whether this is the section we want
                             */
                            if (confParseSectionName
                                (strippedLineBuffer, sectionName)) {
                                /*
                                 * It is the section we want so set the flag
                                 */
                                inSection = 1;
                                sectionFound = 1;
                            }
                        }
                    } else {    /* It's not a section name so assume it is a
                                 * parameter */
                        /*
                         * Are we in the correct section of the config file?
                         */
                        if (inSection) {
                            /*
                             * We are so parse the parameter and deal with it
                             * as appropriate
                             */
                            if (confParseParameter
                                (strippedLineBuffer, keyName, keyValue,
                                 keyValueSize)) {
                                /*
                                 * Found the parameter we are looking for set
                                 * flag and break out of loop
                                 */
                                found = 1;
                                break;
                            }
                        }
                    }
                }
            }
        }
        fclose(conffile);
    } else {
        fprintf(stderr, "Unable to open file %s\n", fileName);
    }
    return found + sectionFound;
}

#define DH89XXCC_NAME "dh89xxcc"
#define DH895XCC_NAME "dh895xcc"
#define C2XXX_NAME "c2xxx"

#define DH89XXCC_INDEX 0
#define DH895XCC_INDEX 1
#define C2XXX_INDEX 2

#define NUM_DEVICES_TYPES 3
#define MAX_NUM_DEVICES 32

int getDevices(unsigned int dev_mask[])
{
    DIR *proc;
    struct dirent *child;
    char *tmp;
    int dev_index;
    int found = 0;
    proc = opendir("/proc");
    if (!proc) {
        WARN("No /proc directory or it cannot be opened\n");
        return 0;
    }
    while ((child = readdir(proc)) != NULL) {
        if (!strncmp(child->d_name, "icp_", 4)) {
            /* there is a /proc/icp_* directory */
            DEBUG("looking for dir %s\n", child->d_name);
            if (strstr(child->d_name, DH89XXCC_NAME)) {
                dev_index = DH89XXCC_INDEX;
            } else if (strstr(child->d_name, DH895XCC_NAME)) {
                dev_index = DH895XCC_INDEX;
            } else if (strstr(child->d_name, C2XXX_NAME)) {
                dev_index = C2XXX_INDEX;
            } else {
                continue;
            }
            if ((tmp = strstr(child->d_name, "dev")) != NULL) {
                if (isdigit(tmp[3])) {
                    int a = atoi(tmp + 3);
                    if ((a >= 0) && (a < MAX_NUM_DEVICES)) {
                        dev_mask[dev_index] |= 1 << a;
                        found = 1;
                    }
                }
            }
        }
    }
    closedir(proc);
    if (!found) {
        WARN("No running QA devices detected \n");
        return 0;
    }
    return 1;
}

int checkLimitDevAccessValue(int *limitDevAccess, char *section_name)
{
    unsigned int devmasks[] = { 0, 0, 0 };
    char *dev_names[] = { DH89XXCC_NAME, DH895XCC_NAME, C2XXX_NAME };
    char configFilePath[CONF_MAX_PATH];
    char configKeyValue[CONF_MAX_LINE_LENGTH] = { 0 };
    int configKeyValueSize = CONF_MAX_LINE_LENGTH;
    int status;
    int i, j;
    if (!getDevices(devmasks)) {
        *limitDevAccess = 0;
        return 0;
    }
    for (j = 0; j < NUM_DEVICES_TYPES; j++)
        for (i = 0; i < MAX_NUM_DEVICES; i++) {
            if ((devmasks[j] & (1 << i))) {
                sprintf(configFilePath, "/etc/%s_qa_dev%d.conf", dev_names[j],
                        i);
            } else {
                continue;
            }
            DEBUG("looking in %s\n", configFilePath);
            status = confCryptoFindKeyValue(configFilePath, section_name,
                                            "LimitDevAccess", configKeyValue,
                                            configKeyValueSize);
            if (status == CONF_FIND_KEY_SECTION_FOUND) {
                /* if the SHIM section was found in the config file but no
                   LimitDevAccess setting,
                   LimitDevAccess is set to 0 */
                *limitDevAccess = 0;
                return 1;
            } else if (status == CONF_FIND_KEY_KEY_FOUND) {
                if (isdigit(configKeyValue[0])) {
                    *limitDevAccess = atoi(configKeyValue);
                    return 1;
                }
            }
        }
    *limitDevAccess = 0;
    return 0;
}
