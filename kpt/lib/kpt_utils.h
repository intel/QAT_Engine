#ifndef __KPT2_UTILS_H__
#define __KPT2_UTILS_H__

#include <stdio.h>

#define NANO_TO_MICROSECS 1000

#ifdef KPT_DEBUG
void kpt_hex_dump(const char *func, const char *var, const unsigned char p[],
             int l)
{
    int i;
    fputc('\n', stderr);
    fprintf(stderr, "%s: %s: Length %d, Address %p \n", func, var, l, p);
    if (NULL != p && l > 0) {
        for (i = 0; i < l; i++) {
            if (i % 32 == 0)
                fputc('\n', stderr);
            else if (i % 8 == 0)
                fputs("- ", stderr);
            fprintf(stderr, "%02x", p[i]);
        }
    }
    fputc('\n', stderr);
}

# define DEBUG(fmt_str, ...)                                   \
    do {                                                       \
        struct timespec ts = { 0 };                            \
        clock_gettime(CLOCK_MONOTONIC, &ts);                   \
        fprintf(stdout,"[DEBUG][%lld.%06ld] PID [%d]"          \
                " Thread [%lx][%s:%d:%s()] "fmt_str,           \
                (long long)ts.tv_sec,                          \
                ts.tv_nsec / NANO_TO_MICROSECS,                \
                getpid(), (long)pthread_self(),  __FILE__,     \
                __LINE__,__func__,##__VA_ARGS__);              \
        fflush(stdout);                                        \
    } while (0)

# define DUMPL(var,p,l) kpt_hex_dump(__func__,var,p,l);

#else

# define DEBUG(...)
# define DUMPL(...)

#endif

#if defined(KPT_WARN) || defined(KPT_DEBUG)

#  define WARN(fmt_str, ...)                                  \
    do {                                                      \
        struct timespec ts = { 0 };                           \
        clock_gettime(CLOCK_MONOTONIC, &ts);                  \
        fprintf(stderr,"[WARN][%lld.%06ld] PID [%d]"          \
                " Thread [%lx][%s:%d:%s()] "fmt_str,          \
                (long long)ts.tv_sec,                         \
                ts.tv_nsec / NANO_TO_MICROSECS,               \
                getpid(), (long)pthread_self(),  __FILE__,    \
                __LINE__,__func__,##__VA_ARGS__);             \
        fflush(stderr);                                       \
    } while (0)

# else

#  define WARN(...)

# endif

#ifdef KPT_DEBUG

# define DUMP_KPT_WRAPPING_DATA(eswk, len_eswk, sig, len_sig, iv, len_iv,      \
                                aad, len_aad)                                  \
    do {                                                                       \
        fprintf(stdout,"=========================\n");                         \
        fprintf(stdout,"KPT Wrapping Metadata\n");                             \
        DUMPL("ESWK", eswk, len_eswk);                                         \
        DUMPL("Signature", sig, len_sig);                                      \
        DUMPL("IV", iv, len_iv);                                               \
        DUMPL("AAD", aad, len_aad);                                            \
        fprintf(stdout,"=========================\n");                         \
        fflush(stdout);                                                        \
    } while (0)

# define DUMP_KPT_RSA_DECRYPT(instance_handle, kpt_handle,                     \
                              op_done, opData, output_buf)                     \
    do {                                                                       \
       fprintf(stdout,"=========================\n");                          \
       fprintf(stdout,"RSA Decrypt Request: %p\n", opData);                    \
       fprintf(stdout,"instance_handle = %p\n", instance_handle);              \
       fprintf(stdout,"KPT handle = 0x%lx\n", kpt_handle);                     \
       fprintf(stdout,"op_done = %p\n", op_done);                              \
       fprintf(stdout,"opData: pRecipientPrivateKey->version = %d\n",          \
               opData->pRecipientPrivateKey->version);                         \
       fprintf(stdout,"opData: pRecipientPrivateKey"                           \
               "->privateKeyRepType = %d\n",                                   \
               opData->pRecipientPrivateKey->privateKeyRepType);               \
       DUMPL("opData: pRecipientPrivateKey->privateKeyRep1.privateKey.pData",  \
              opData->pRecipientPrivateKey->privateKeyRep1.privateKey.pData,   \
              opData->pRecipientPrivateKey->privateKeyRep1.privateKey.         \
              dataLenInBytes);                                                 \
       DUMPL("opData: pRecipientPrivateKey->privateKeyRep2.privateKey.pData",  \
              opData->pRecipientPrivateKey->privateKeyRep2.privateKey.pData,   \
              opData->pRecipientPrivateKey->privateKeyRep2.privateKey.         \
              dataLenInBytes);                                                 \
       DUMPL("opData: inputData.pData", opData->inputData.pData,               \
              opData->inputData.dataLenInBytes);                               \
       fprintf(stdout,"output_buf = %p\n", output_buf);                        \
       fprintf(stdout,"=========================\n");                          \
       fflush(stdout);                                                         \
    } while (0)

# define DUMP_KPT_ECDSA_SIGN(instance_handle, kpt_handle,                      \
                             opData, pResultR, pResultS)                       \
    do {                                                                       \
        fprintf(stdout,"=========================\n");                         \
        fprintf(stdout,"KPT ECDSA Sign Request: %p\n", opData);                \
        fprintf(stdout,"instance_handle ptr = %p\n", instance_handle);         \
        fprintf(stdout,"KPT handle = 0x%lx\n", kpt_handle);                    \
        DUMPL("m.pData", opData->m.pData, opData->m.dataLenInBytes);           \
        DUMPL("WPK data", opData->privateKey.pData,                            \
              opData->privateKey.dataLenInBytes);                              \
        fprintf(stdout,"pResultR->dataLenInBytes = %u "                        \
                "pResultR->pData = %p\n",                                      \
                pResultR->dataLenInBytes, pResultR->pData);                    \
        fprintf(stdout,"pResultS->dataLenInBytes = %u "                        \
                "pResultS->pData = %p\n",                                      \
                pResultS->dataLenInBytes, pResultS->pData);                    \
        fprintf(stdout,"=========================\n");                         \
        fflush(stdout);                                                        \
    } while (0)

#else

# define DUMP_KPT_WRAPPING_DATA(...)
# define DUMP_KPT_RSA_DECRYPT(...)
# define DUMP_KPT_ECDSA_SIGN(...)

#endif

#endif