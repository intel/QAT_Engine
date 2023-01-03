/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_QATERR_H
# define HEADER_QATERR_H

# include <openssl/symhacks.h>

# define QATerr(f, r) ERR_QAT_error((f), (r), OPENSSL_FILE, OPENSSL_LINE)


# ifdef  __cplusplus
extern "C" {
# endif
int ERR_load_QAT_strings(void);
void ERR_unload_QAT_strings(void);
void ERR_QAT_error(int function, int reason, char *file, int line);
# ifdef  __cplusplus
}
# endif

/*
 * QAT function codes.
 */
# define QAT_F_AES_GCM_TLS_CIPHER                         100
# define QAT_F_BUILD_DECRYPT_OP_BUF                       101
# define QAT_F_BUILD_ENCRYPT_OP_BUF                       102
# define QAT_F_CRT_COMBINE                                103
# define QAT_F_CRT_PREPARE                                104
# define QAT_F_ENGINE_FINISH_BEFORE_FORK_HANDLER          105
# define QAT_F_ENGINE_INIT_CHILD_AT_FORK_HANDLER          106
# define QAT_F_ENGINE_QAT                                 107
# define QAT_F_EVENT_POLL_FUNC                            108
# define QAT_F_MB_ECDH_COMPUTE_KEY                        109
# define QAT_F_MB_ECDH_GENERATE_KEY                       110
# define QAT_F_MB_ECDSA_SIGN                              111
# define QAT_F_MB_ECDSA_SIGN_SETUP                        112
# define QAT_F_MB_ECDSA_SIGN_SIG                          113
# define QAT_F_MB_ECDSA_SM2_SIGN                          114
# define QAT_F_MB_ECDSA_SM2_VERIFY                        115
# define QAT_F_MB_SM2_CTRL                                116
# define QAT_F_MB_SM2_INIT                                117
# define QAT_F_MULTIBUFF_INIT                             118
# define QAT_F_MULTIBUFF_RSA_ADD_PADDING_PRIV_ENC         119
# define QAT_F_MULTIBUFF_RSA_ADD_PADDING_PUB_ENC          120
# define QAT_F_MULTIBUFF_RSA_PRIV_DEC                     121
# define QAT_F_MULTIBUFF_RSA_PRIV_ENC                     122
# define QAT_F_MULTIBUFF_RSA_PUB_DEC                      123
# define QAT_F_MULTIBUFF_RSA_PUB_ENC                      124
# define QAT_F_MULTIBUFF_VALIDATE_ECX_DERIVE              125
# define QAT_F_MULTIBUFF_X25519_DERIVE                    126
# define QAT_F_MULTIBUFF_X25519_KEYGEN                    127
# define QAT_F_OSSL_SM2_COMPUTE_Z_DIGEST                  128
# define QAT_F_POLL_INSTANCES                             129
# define QAT_F_QAT_ADJUST_THREAD_AFFINITY                 130
# define QAT_F_QAT_AES_GCM_CIPHER                         131
# define QAT_F_QAT_AES_GCM_CLEANUP                        132
# define QAT_F_QAT_AES_GCM_CTRL                           133
# define QAT_F_QAT_AES_GCM_INIT                           134
# define QAT_F_QAT_AES_GCM_SESSION_INIT                   135
# define QAT_F_QAT_AES_GCM_TLS_CIPHER                     136
# define QAT_F_QAT_CHACHA20_POLY1305_CLEANUP              137
# define QAT_F_QAT_CHACHA20_POLY1305_CTRL                 138
# define QAT_F_QAT_CHACHA20_POLY1305_DO_CIPHER            139
# define QAT_F_QAT_CHACHA20_POLY1305_INIT                 140
# define QAT_F_QAT_CHACHA20_POLY1305_INIT_KEY_IV          141
# define QAT_F_QAT_CHACHA20_POLY1305_MAC_KEYGEN           142
# define QAT_F_QAT_CHACHA20_POLY1305_TLS_CIPHER           143
# define QAT_F_QAT_CHACHAPOLY_SESSION_DATA_INIT           144
# define QAT_F_QAT_CHACHAPOLY_SETUP_OP_PARAMS             145
# define QAT_F_QAT_CREATE_SM4_CIPHER_METH                 146
# define QAT_F_QAT_CRYPTO_CALLBACKFN                      147
# define QAT_F_QAT_DH_COMPUTE_KEY                         148
# define QAT_F_QAT_DH_GENERATE_KEY                        149
# define QAT_F_QAT_DSA_DO_SIGN                            150
# define QAT_F_QAT_DSA_DO_VERIFY                          151
# define QAT_F_QAT_DSA_SIGN_SETUP                         152
# define QAT_F_QAT_ECDH_COMPUTE_KEY                       153
# define QAT_F_QAT_ECDH_GENERATE_KEY                      154
# define QAT_F_QAT_ECDSA_DO_SIGN                          155
# define QAT_F_QAT_ECDSA_DO_VERIFY                        156
# define QAT_F_QAT_ECDSA_SIGN                             157
# define QAT_F_QAT_ECDSA_VERIFY                           158
# define QAT_F_QAT_ENGINE_CTRL                            159
# define QAT_F_QAT_ENGINE_ECDH_COMPUTE_KEY                160
# define QAT_F_QAT_FD_CLEANUP                             161
# define QAT_F_QAT_FINISH_INT                             162
# define QAT_F_QAT_GET_DH_METHODS                         163
# define QAT_F_QAT_GET_DSA_METHODS                        164
# define QAT_F_QAT_GET_EC_METHODS                         165
# define QAT_F_QAT_GET_RSA_METHODS                        166
# define QAT_F_QAT_HKDF_DERIVE                            167
# define QAT_F_QAT_HKDF_INIT                              168
# define QAT_F_QAT_HKDF_PMETH                             169
# define QAT_F_QAT_INIT                                   170
# define QAT_F_QAT_INIT_OP_DONE                           171
# define QAT_F_QAT_INIT_OP_DONE_PIPE                      172
# define QAT_F_QAT_INIT_OP_DONE_RSA_CRT                   173
# define QAT_F_QAT_MOD_EXP                                174
# define QAT_F_QAT_PKEY_ECX_DERIVE25519                   175
# define QAT_F_QAT_PKEY_ECX_DERIVE448                     176
# define QAT_F_QAT_PKEY_ECX_KEYGEN                        177
# define QAT_F_QAT_PRF_PMETH                              178
# define QAT_F_QAT_PRF_TLS_DERIVE                         179
# define QAT_F_QAT_REMAP_INSTANCES                        180
# define QAT_F_QAT_RSA_DECRYPT                            181
# define QAT_F_QAT_RSA_DECRYPT_CRT                        182
# define QAT_F_QAT_RSA_ENCRYPT                            183
# define QAT_F_QAT_RSA_PRIV_DEC                           184
# define QAT_F_QAT_RSA_PRIV_ENC                           185
# define QAT_F_QAT_RSA_PUB_DEC                            186
# define QAT_F_QAT_RSA_PUB_ENC                            187
# define QAT_F_QAT_SESSION_DATA_INIT                      188
# define QAT_F_QAT_SETUP_OP_PARAMS                        189
# define QAT_F_QAT_SET_INSTANCE_FOR_THREAD                190
# define QAT_F_QAT_SHA3_CLEANUP                           191
# define QAT_F_QAT_SHA3_COPY                              192
# define QAT_F_QAT_SHA3_CTRL                              193
# define QAT_F_QAT_SHA3_FINAL                             194
# define QAT_F_QAT_SHA3_SESSION_DATA_INIT                 195
# define QAT_F_QAT_SHA3_SETUP_PARAM                       196
# define QAT_F_QAT_SHA3_UPDATE                            197
# define QAT_F_QAT_SM4_CBC_CLEANUP                        198
# define QAT_F_QAT_SM4_CBC_DO_CIPHER                      199
# define QAT_F_QAT_SM4_CBC_INIT                           200
# define QAT_F_QAT_SW_SM3_FINAL                           201
# define QAT_F_QAT_SW_SM3_INIT                            202
# define QAT_F_QAT_SW_SM3_UPDATE                          203
# define QAT_F_QAT_SYM_PERFORM_OP                         204
# define QAT_F_QAT_VALIDATE_ECX_DERIVE                    205
# define QAT_F_QAT_X25519_PMETH                           206
# define QAT_F_QAT_X448_PMETH                             207
# define QAT_F_VAESGCM_CIPHERS_CTRL                       208
# define QAT_F_VAESGCM_CIPHERS_DO_CIPHER                  209
# define QAT_F_VAESGCM_CIPHERS_INIT                       210
# define QAT_F_VAESGCM_INIT_GCM                           211
# define QAT_F_VAESGCM_INIT_IPSEC_MB_MGR                  212
# define QAT_F_VAESGCM_INIT_KEY                           213

/*
 * QAT reason codes.
 */
# define QAT_R_AAD_INVALID_PTR                            100
# define QAT_R_AAD_LEN_INVALID                            101
# define QAT_R_AAD_MALLOC_FAILURE                         102
# define QAT_R_ADD_M2_FAILURE                             103
# define QAT_R_ADJUST_DELTA_M1_M2_FAILURE                 104
# define QAT_R_ALLOC_E_CHECK_FAILURE                      105
# define QAT_R_ALLOC_MULTIBUFF_RSA_METH_FAILURE           106
# define QAT_R_ALLOC_QAT_DSA_METH_FAILURE                 107
# define QAT_R_ALLOC_QAT_RSA_METH_FAILURE                 108
# define QAT_R_ALLOC_QAT_X25519_METH_FAILURE              109
# define QAT_R_ALLOC_QAT_X448_METH_FAILURE                110
# define QAT_R_ALLOC_TAG_FAILURE                          111
# define QAT_R_BUF_CONV_FAIL                              112
# define QAT_R_CAPABILITY_FAILURE                         113
# define QAT_R_CHACHAPOLY_CTX_NULL                        114
# define QAT_R_CLOSE_READFD_FAILURE                       115
# define QAT_R_COMPUTE_FAILURE                            116
# define QAT_R_COMPUTE_H_MULTIPLY_Q_FAILURE               117
# define QAT_R_CP_BUF_MALLOC_FAILURE                      118
# define QAT_R_CQ_BUF_MALLOC_FAILURE                      119
# define QAT_R_CREATE_FREELIST_QUEUE_FAILURE              120
# define QAT_R_CTX_MALLOC_FAILURE                         121
# define QAT_R_CTX_NULL                                   122
# define QAT_R_CURVE_COORDINATE_PARAMS_CONVERT_TO_FB_FAILURE 123
# define QAT_R_CURVE_DOES_NOT_SUPPORT_SIGNING             124
# define QAT_R_C_MODULO_P_FAILURE                         125
# define QAT_R_C_MODULO_Q_FAILURE                         126
# define QAT_R_C_P_Q_CP_CQ_MALLOC_FAILURE                 127
# define QAT_R_DEC_OP_DATA_MALLOC_FAILURE                 128
# define QAT_R_DERIVE_FAILURE                             129
# define QAT_R_DGSTLEN_INVALID                            130
# define QAT_R_DGST_BN_CONV_FAILURE                       131
# define QAT_R_DH_NULL                                    132
# define QAT_R_DLEN_INVALID                               133
# define QAT_R_DSA_DGST_NULL                              134
# define QAT_R_DSA_DGST_SIG_NULL                          135
# define QAT_R_ECDH_GET_AFFINE_COORD_FAILED               136
# define QAT_R_ECDH_GROUP_NULL                            137
# define QAT_R_ECDH_PRIVATE_KEY_NULL                      138
# define QAT_R_ECDH_PRIV_KEY_PUB_KEY_NULL                 139
# define QAT_R_ECDH_SET_AFFINE_COORD_FAILED               140
# define QAT_R_ECDH_UNKNOWN_FIELD_TYPE                    141
# define QAT_R_ECDSA_MALLOC_FAILURE                       142
# define QAT_R_ECDSA_SIGN_FAILURE                         143
# define QAT_R_ECDSA_SIGN_NULL                            144
# define QAT_R_ECDSA_SIGN_SETUP_FAILURE                   145
# define QAT_R_ECDSA_SIG_MALLOC_FAILURE                   146
# define QAT_R_ECDSA_SIG_SET_R_S_FAILURE                  147
# define QAT_R_ECDSA_VERIFY_FAILURE                       148
# define QAT_R_ECDSA_VERIFY_NULL                          149
# define QAT_R_ECKEY_GROUP_PUBKEY_SIG_NULL                150
# define QAT_R_EC_KEY_GROUP_PRIV_KEY_NULL                 151
# define QAT_R_EC_LIB                                     152
# define QAT_R_EC_POINT_RETRIEVE_FAILURE                  153
# define QAT_R_ENC_OP_DATA_MALLOC_FAILURE                 154
# define QAT_R_ENGINE_CTRL_CMD_FAILURE                    155
# define QAT_R_ENGINE_INIT_FAILURE                        156
# define QAT_R_ENGINE_NULL                                157
# define QAT_R_EPOLL_CREATE_FAILURE                       158
# define QAT_R_EPOLL_CTL_FAILURE                          159
# define QAT_R_EVENTS_MALLOC_FAILURE                      160
# define QAT_R_EVP_LIB                                    161
# define QAT_R_FALLBACK_POINTER_NULL                      162
# define QAT_R_FIELD_SIZE_INVALID                         163
# define QAT_R_FREE_DH_METH_FAILURE                       164
# define QAT_R_FREE_MULTIBUFF_RSA_METH_FAILURE            165
# define QAT_R_FREE_QAT_DSA_METH_FAILURE                  166
# define QAT_R_FREE_QAT_RSA_METH_FAILURE                  167
# define QAT_R_GCM_TAG_VERIFY_FAILURE                     168
# define QAT_R_GET_COFACTOR_FAILURE                       169
# define QAT_R_GET_FILE_DESCRIPTOR_FAILURE                170
# define QAT_R_GET_GROUP_FAILURE                          171
# define QAT_R_GET_INSTANCE_FAILURE                       172
# define QAT_R_GET_INSTANCE_INFO_FAILURE                  173
# define QAT_R_GET_NUM_INSTANCE_FAILURE                   174
# define QAT_R_GET_ORDER_FAILURE                          175
# define QAT_R_GET_PQG_FAILURE                            176
# define QAT_R_GET_PRIV_KEY_FAILURE                       177
# define QAT_R_GROUP_PRIV_KEY_PUB_KEY_NULL                178
# define QAT_R_H_CONVERT_TO_FB_FAILURE                    179
# define QAT_R_ICP_SAL_USERSTART_FAIL                     180
# define QAT_R_ID_TOO_LARGE                               181
# define QAT_R_INITIALIZE_CTX_FAILURE                     182
# define QAT_R_INIT_FAILURE                               183
# define QAT_R_INPUT_DATA_MALLOC_FAILURE                  184
# define QAT_R_INPUT_PARAM_INVALID                        185
# define QAT_R_INSTANCE_HANDLE_MALLOC_FAILURE             186
# define QAT_R_INSTANCE_UNAVAILABLE                       187
# define QAT_R_INTERNAL_ERROR                             188
# define QAT_R_INVALID_ATTACHED_TAG                       189
# define QAT_R_INVALID_CTRL_TYPE                          190
# define QAT_R_INVALID_CURVE                              191
# define QAT_R_INVALID_HASH_DATA                          192
# define QAT_R_INVALID_INPUT_LENGTH                       193
# define QAT_R_INVALID_INPUT_PARAMETER                    194
# define QAT_R_INVALID_IVLEN                              195
# define QAT_R_INVALID_LEN                                196
# define QAT_R_INVALID_PEER_KEY                           197
# define QAT_R_INVALID_PRIVATE_KEY                        198
# define QAT_R_INVALID_PTR                                199
# define QAT_R_INVALID_PTR_IV                             200
# define QAT_R_INVALID_PUB_KEY                            201
# define QAT_R_INVALID_QCTX_MEMORY                        202
# define QAT_R_INVALID_TAG_LEN                            203
# define QAT_R_INVALID_TYPE                               204
# define QAT_R_IN_KINV_CONVERT_TO_FB_FAILURE              205
# define QAT_R_IN_R_CONVERT_TO_FB_FAILURE                 206
# define QAT_R_IPSEC_MGR_NULL                             207
# define QAT_R_IV_ALLOC_FAILURE                           208
# define QAT_R_IV_GEN_INVALID                             209
# define QAT_R_IV_INVALID                                 210
# define QAT_R_IV_LEN_NOT_SUPPORTED                       211
# define QAT_R_IV_MALLOC_FAILURE                          212
# define QAT_R_IV_NULL_PTR_INVALID                        213
# define QAT_R_IV_NVALID                                  214
# define QAT_R_KEYGEN_FAILURE                             215
# define QAT_R_KEYS_NOT_SET                               216
# define QAT_R_KEY_IV_NOT_SET                             217
# define QAT_R_KEY_MALLOC_FAILURE                         218
# define QAT_R_KEY_NULL                                   219
# define QAT_R_K_ALLOCATE_FAILURE                         220
# define QAT_R_K_CONVERT_TO_FB_FAILURE                    221
# define QAT_R_K_ORDER_CONVERT_TO_FB_FAILURE              222
# define QAT_R_K_RAND_GENERATE_FAILURE                    223
# define QAT_R_M1_DEDUCT_M2_FAILURE                       224
# define QAT_R_M1_M2_P_Q_QINV_TMP_MALLOC_FAILURE          225
# define QAT_R_MALLOC_FAILURE                             226
# define QAT_R_MAX_RETRIES_EXCEEDED                       227
# define QAT_R_MB_FREE_EC_METHOD_FAILURE                  228
# define QAT_R_MB_GET_EC_METHOD_MALLOC_FAILURE            229
# define QAT_R_MODULO_P_FAILURE                           230
# define QAT_R_MOD_GET_NEXT_INST_FAIL                     231
# define QAT_R_MOD_LN_MOD_EXP_FAIL                        232
# define QAT_R_MOD_SETUP_ASYNC_EVENT_FAIL                 233
# define QAT_R_MULTIPLY_QINV_FAILURE                      234
# define QAT_R_NID_NOT_SUPPORTED                          235
# define QAT_R_NO_PARAMETERS_SET                          236
# define QAT_R_N_E_CONVERT_TO_FB_FAILURE                  237
# define QAT_R_N_E_NULL                                   238
# define QAT_R_OP1_BASE_PDATA_MALLOC_FAILURE              239
# define QAT_R_OP2_BASE_PDATA_MALLOC_FAILURE              240
# define QAT_R_OPDATA_A_PDATA_MALLOC_FAILURE              241
# define QAT_R_OPDATA_DATA_MALLOC_FAILURE                 242
# define QAT_R_OPDATA_MALLOC_FAILURE                      243
# define QAT_R_OPDATA_PDATA_MALLOC_FAILURE                244
# define QAT_R_OPDATA_ZPDATA_MALLOC_FAILURE               245
# define QAT_R_OPDCRT_NULL                                246
# define QAT_R_OPDONE_NULL                                247
# define QAT_R_OPDPIPE_NULL                               248
# define QAT_R_ORDER_MALLOC_FAILURE                       249
# define QAT_R_OUT1_PDATA_MALLOC_FAILURE                  250
# define QAT_R_OUT2_PDATA_MALLOC_FAILURE                  251
# define QAT_R_OUTPUT_BUF_MALLOC_FAILURE                  252
# define QAT_R_OUTPUT_BUF_PDATA_MALLOC_FAILURE            253
# define QAT_R_OUTX_MALLOC_FAILURE                        254
# define QAT_R_OUTX_OUTY_LEN_NULL                         255
# define QAT_R_OUTY_MALLOC_FAILURE                        256
# define QAT_R_PADDING_UNKNOWN                            257
# define QAT_R_POLLING_THREAD_CREATE_FAILURE              258
# define QAT_R_POLLING_THREAD_SEM_INIT_FAILURE            259
# define QAT_R_POLLING_THREAD_SIGMASK_FAILURE             260
# define QAT_R_POLL_INSTANCE_FAILURE                      261
# define QAT_R_POPDATA_A_PDATA_MALLOC_FAILURE             262
# define QAT_R_POPDATA_MALLOC_FAILURE                     263
# define QAT_R_POPDATA_PCURVE_MALLOC_FAILURE              264
# define QAT_R_PPV_MALLOC_FAILURE                         265
# define QAT_R_PPV_PDATA_MALLOC_FAILURE                   266
# define QAT_R_PRESULTR_MALLOC_FAILURE                    267
# define QAT_R_PRESULTR_PDATA_MALLOC_FAILURE              268
# define QAT_R_PRESULTS_MALLOC_FAILURE                    269
# define QAT_R_PRESULTS_PDATA_MALLOC_FAILURE              270
# define QAT_R_PRESULTX_MALLOC_FAILURE                    271
# define QAT_R_PRESULTX_PDATA_MALLOC_FAILURE              272
# define QAT_R_PRESULTY_LENGTH_CHECK_FAILURE              273
# define QAT_R_PRESULTY_MALLOC_FAILURE                    274
# define QAT_R_PRESULTY_PDATA_MALLOC_FAILURE              275
# define QAT_R_PRIV_KEY_DUPLICATE_FAILURE                 276
# define QAT_R_PRIV_KEY_MALLOC_FAILURE                    277
# define QAT_R_PRIV_KEY_M_XG_YG_A_B_P_CONVERT_TO_FB_FAILURE 278
# define QAT_R_PRIV_KEY_NULL                              279
# define QAT_R_PRIV_KEY_RAND_GENERATE_FAILURE             280
# define QAT_R_PRIV_KEY_XG_YG_A_B_P_CONVERT_TO_FB_FAILURE 281
# define QAT_R_PRIV_KEY_XP_YP_A_B_P_CONVERT_TO_FB_FAILURE 282
# define QAT_R_PTHREAD_CREATE_FAILURE                     283
# define QAT_R_PTHREAD_GETAFFINITY_FAILURE                284
# define QAT_R_PTHREAD_JOIN_FAILURE                       285
# define QAT_R_PTHREAD_SETAFFINITY_FAILURE                286
# define QAT_R_PUB_KEY_DUPLICATE_FAILURE                  287
# define QAT_R_PUB_KEY_MALLOC_FAILURE                     288
# define QAT_R_PUB_KEY_NULL                               289
# define QAT_R_P_A_B_XG_YG_MALLOC_FAILURE                 290
# define QAT_R_P_A_B_XG_YG_M_K_R_ORDER_MALLOC_FAILURE     291
# define QAT_R_P_A_B_XG_YG_XP_YP_M_ORDER_FAILURE          292
# define QAT_R_P_A_B_XP_YP_FAILURE                        293
# define QAT_R_P_A_B_XP_YP_MALLOC_FAILURE                 294
# define QAT_R_P_G_PRIV_KEY_CONVERT_TO_FB_FAILURE         295
# define QAT_R_P_PUB_PRIV_KEY_CONVERT_TO_FB_FAILURE       296
# define QAT_R_P_Q_DMP_DMQ_CONVERT_TO_FB_FAILURE          297
# define QAT_R_P_Q_DMP_DMQ_IQMP_NULL                      298
# define QAT_R_P_Q_G_NULL                                 299
# define QAT_R_P_Q_G_X_K_CONVERT_TO_FB_FAILURE            300
# define QAT_R_P_Q_G_Y_Z_R_S_CONVERT_TO_FB_FAILURE        301
# define QAT_R_QAT_ALLOC_DH_METH_FAILURE                  302
# define QAT_R_QAT_CREATE_ENGINE_FAILURE                  303
# define QAT_R_QAT_ECDSA_DO_SIGN_FAIL                     304
# define QAT_R_QAT_FREE_EC_METHOD_FAILURE                 305
# define QAT_R_QAT_GET_EC_METHOD_MALLOC_FAILURE           306
# define QAT_R_QAT_SET_DH_METH_FAILURE                    307
# define QAT_R_QCTX_CTX_NULL                              308
# define QAT_R_QCTX_NULL                                  309
# define QAT_R_RAND_BYTES_FAILURE                         310
# define QAT_R_RAND_FAILURE                               311
# define QAT_R_RAND_GENERATE_FAILURE                      312
# define QAT_R_RESULT_PDATA_ALLOC_FAIL                    313
# define QAT_R_RETRIEVE_EC_POINT_FAILURE                  314
# define QAT_R_RETRIEVE_ORDER_FAILURE                     315
# define QAT_R_RSA_FROM_TO_NULL                           316
# define QAT_R_RSA_OUTPUT_BUF_PDATA_MALLOC_FAILURE        317
# define QAT_R_R_Q_COMPARE_FAILURE                        318
# define QAT_R_SECRET_KEY_MALLOC_FAILURE                  319
# define QAT_R_SECRET_KEY_PDATA_MALLOC_FAILURE            320
# define QAT_R_SEM_POST_FAILURE                           321
# define QAT_R_SETUP_ASYNC_EVENT_FAILURE                  322
# define QAT_R_SET_ADDRESS_TRANSLATION_FAILURE            323
# define QAT_R_SET_FILE_DESCRIPTOR_NONBLOCKING_FAILURE    324
# define QAT_R_SET_INSTANCE_FAILURE                       325
# define QAT_R_SET_MULTIBUFF_RSA_METH_FAILURE             326
# define QAT_R_SET_NOTIFICATION_CALLBACK_FAILURE          327
# define QAT_R_SET_POLLING_THREAD_AFFINITY_FAILURE        328
# define QAT_R_SET_PRIV_KEY_FAILURE                       329
# define QAT_R_SET_QAT_DSA_METH_FAILURE                   330
# define QAT_R_SET_QAT_RSA_METH_FAILURE                   331
# define QAT_R_SET_TAG_INVALID_OP                         332
# define QAT_R_SHA3_CTX_NULL                              333
# define QAT_R_SIG_GET_R_S_FAILURE                        334
# define QAT_R_SIG_MALLOC_FAILURE                         335
# define QAT_R_SM3_FINAL_FAILURE                          336
# define QAT_R_SM3_INIT_FAILURE                           337
# define QAT_R_SM3_UPDATE_FAILURE                         338
# define QAT_R_SM4_GET_INSTANCE_FAILED                    339
# define QAT_R_SM4_GET_SESSIONCTX_SIZE_FAILED             340
# define QAT_R_SM4_MALLOC_FAILED                          341
# define QAT_R_SM4_NO_QAT_INSTANCE_AVAILABLE              342
# define QAT_R_SM4_NULL_CKEY                              343
# define QAT_R_SM4_NULL_CTX_OR_KEY                        344
# define QAT_R_SM4_NULL_POINTER                           345
# define QAT_R_SM4_NULL_QCTX                              346
# define QAT_R_SM4_QAT_CONTEXT_NOT_INITIALISED            347
# define QAT_R_SM4_QAT_INITSESSION_FAILED                 348
# define QAT_R_SM4_QAT_SUBMIT_REQUEST_FAILED              349
# define QAT_R_SM4_REMOVE_SESSION_FAILED                  350
# define QAT_R_SM4_SETUP_META_DATA_FAILED                 351
# define QAT_R_SM4_SET_METHODS_FAILED                     352
# define QAT_R_SSD_MALLOC_FAILURE                         353
# define QAT_R_SSD_NULL                                   354
# define QAT_R_START_INSTANCE_FAILURE                     355
# define QAT_R_STOP_INSTANCE_FAILURE                      356
# define QAT_R_SW_GET_COMPUTE_KEY_PFUNC_NULL              357
# define QAT_R_SW_GET_KEYGEN_PFUNC_NULL                   358
# define QAT_R_SW_GET_SIGN_PFUNC_NULL                     359
# define QAT_R_SW_GET_SIGN_SETUP_PFUNC_NULL               360
# define QAT_R_SW_GET_SIGN_SIG_PFUNC_NULL                 361
# define QAT_R_SW_GET_VERIFY_SIG_PFUNC_NULL               362
# define QAT_R_SW_METHOD_NULL                             363
# define QAT_R_S_NULL                                     364
# define QAT_R_S_Q_COMPARE_FAILURE                        365
# define QAT_R_UNKNOWN_PADDING                            366
# define QAT_R_UNKNOWN_PADDING_TYPE                       367
# define QAT_R_WAKE_PAUSE_JOB_FAILURE                     368
# define QAT_R_X_Y_TX_TY_BN_MALLOC_FAILURE                369
# define QAT_R_X_Y_Z_MALLOC_FAILURE                       370
# define QAT_R_Z_ALLOCATE_FAILURE                         371

#endif
