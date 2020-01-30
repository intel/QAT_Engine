/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
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

#ifndef QATPARSECONF_H
# define QATPARSECONF_H

# include <stdio.h>

/*
 * The maximum amount of characters allowed per line in the config file
 */
# define CONF_MAX_LINE_LENGTH 160

/*
 * The number of arguments when we split a line of the form: "<arg1> =
 * <arg2>"
 */
# define CONF_PARAM_EXP_NUM_ARGS 2

/*
 * The maximum length of the path and filename to where the driver
 * configuration file is stored
 */
# define CONF_MAX_PATH 1024

# define CONF_FIND_KEY_KEY_FOUND 2
# define CONF_FIND_KEY_SECTION_FOUND 1
# define CONF_FIND_KEY_FAILED 0
/***********************************************************************
 * function:
 *         confCryptoFindKeyValue(char * filename
 *                          char * sectionName, char * keyName
 *                          char * keyValue, size_t keyValueSize)
 * @description
 *     This function will open the config file at the supplied path.
 *     Parse the config file for the specified section and then parse
 *     for the specified key name. If the key name is found then the
 *     function will return 1 and copy the associated key value into
 *     the string supplied as the keyValue parameter. If the key
 *     name is not found then the function will return 0 and the
 *     keyValue string will not be populated.
 * @param[in] filename - a string containing the path and filename of
 *                       the config file to parse.
 * @param[in] sectionName - a string containing the section name to
 *                          match.
 * @param[in] keyName - a string containing the key name we are
 *                      trying to match.
 * @param[in, out] keyValue - This parameter should be passed in as
 *                            an allocated string. If a match is found
 *                            for the sectionName and keyName then the
 *                            key value associated with the key name
 *                            will be copied into this string.
 * @param[in] keyValueSize - the size of the allocated string passed
 *                           in as keyValue. This allows size checking
 *                           so we don't try and copy a key value that
 *                           is too large into the keyValue string.
 * @retval int - Return 2 if a key value was found.
 *               Return 1 if the section was found
 *               Return 0 if the key value nor section was not found or any errors occured.
 *
 **********************************************************************/
int confCryptoFindKeyValue(char *fileName,
                           char *sectionName, char *keyName,
                           char *keyValue, size_t keyValueSize);

 /***********************************************************************
  * function:
  *         checkLimitDevAccessValue(int * limitDevAccess,
  *                                  char * section_name);
  * @description
  *     This function will go through config files of running QA devices
  *     and look for value of LimitDevAccess parameter in the section, whose name
  *     is given in the section_name parameter. The value of LimitDevAccess found
  *     in first config file that contains section_name section. If the first config
  *     file that contains section_name section does not have LimitDevAccess set, then
  *     it is assumed that LimitDevAccess=1
  * @param[out] limitDevAccess - pointer to where the returned LimitDevAccess value
  *                             will be stored
  * @param[in] sectionName - a string containing the section name to
  *                          match.
  * @retval int - Return 1 the LimitDevAccess value was found.
  *               Return 0 the LimitDevAccess could not be found, zero is returned in
  *                         limitDevAccess
  *
  **********************************************************************/
int checkLimitDevAccessValue(int *limitDevAccess, char *section_name);

 /***********************************************************************
  * function:
  *         getDevices(unsigned int dev_mask[])
  *
  * @description
  *     This function will check the availability of Acceleration devices
  *     and if found, it will set the corresponding index to 1.
  *
  * @param[out] dev_mask - Corresponding dev index will be set to 1.
  *
  * @param[in] dev_mask - An empty array with all the values set to 0.
  *
  * @retval int - Return 1 The acceleration devices are found
  *               Return 0 No Acceleration device is found
  *
  **********************************************************************/
int getDevices(unsigned int dev_mask[], int *upstream_flag);
#endif                          /* QATPARSECONF_H */
