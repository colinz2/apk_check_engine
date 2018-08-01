#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>

#include <string>
#include <iostream>
#include <vector>
// using namespace std;
// string to_string(X509_NAME* name)
// {
//     BIO* mem = BIO_new(BIO_s_mem());
//     if (mem == NULL)
//         return NULL;

//     if (X509_NAME_print_ex(mem, name, 0, XN_FLAG_RFC2253) < 0) {
//         return NULL;
//     }
//     string str;
//     char buf[128];     
//     while((BIO_gets(mem, &buf[0], sizeof(buf))) > 0)
//     {
//         str.append(buf);
//     }
//     BIO_free(mem);
//     return str;
// }

// int main()
// {
//     FILE* fp;
//     if (!(fp = fopen("CERT.RSA", "rb")))
//     {
//         fprintf(stderr, "Error reading input pkcs7 file\n" );
//         exit(1);
//     }

//     PKCS7* pkcs7 = d2i_PKCS7_fp(fp, NULL);
//     X509* cert = sk_X509_pop(pkcs7->d.sign->cert);
//     string subject = to_string(X509_get_subject_name(cert));
//     string issuer = to_string(X509_get_issuer_name(cert));
//     char *modulus = BN_bn2dec(X509_get_pubkey(cert)->pkey.rsa->n);
//     cout << subject << endl;
//     OPENSSL_free(modulus);
//     fclose(fp);
//     return 0;
// }

static void phex(const uint8_t* str, int len)
{
    int i;
    for(i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static std::string thumbprint(X509* x509)
{
    static const char hexbytes[32] = "0123456789ABCDEF";
    unsigned int md_size;
    unsigned char md[EVP_MAX_MD_SIZE];
    std::string out;
    char a[32] = {0};
    const EVP_MD * digest = EVP_get_digestbyname("sha256");
    X509_digest(x509, digest, md, &md_size);
    for (int pos = 0; pos < md_size; pos++) {
        a[0] = hexbytes[(md[pos] & 0xf0) >> 4];
        a[1] = hexbytes[(md[pos] & 0x0f)];
        out.append(a);
    }
    return out;
}

std::vector<uint8_t> digest(int index, PKCS7* pkcs7) 
{
  STACK_OF(PKCS7_SIGNER_INFO)* infos = PKCS7_get_signer_info(pkcs7);

  PKCS7_SIGNER_INFO* info = sk_PKCS7_SIGNER_INFO_value(infos, index);
  std::vector<uint8_t> ret;

  if (info) {
    int length = ASN1_STRING_length(info->enc_digest);
    const uint8_t* data = ASN1_STRING_get0_data(info->enc_digest);
    phex(data, length);
    for (int i = 0; i < length; i ++) {
        ret.push_back(data[i]);
    }
  }
  return ret;
}

int ParseAnroidCer(const char* file_name, char* buf, int buf_len)
{
    BIO* bio = NULL;
    int ret = 0;
    if (file_name != NULL) {
        bio = BIO_new_file(file_name, "r");
    } else {
        bio = BIO_new(BIO_s_mem());
        BIO_write(bio, buf, buf_len);
    }

    do {
        if (NULL == bio) {
            printf("NULL == bio \n");
            ret = -1;
            break;
        }
        PKCS7* pkcs7;
        pkcs7 = d2i_PKCS7_bio(bio, NULL);
        if (pkcs7 == NULL) {
            printf("%s\n", "PEM_read_bio_PKCS7");
            ret = 2;
            break;
        }
        //
        if (!PKCS7_type_is_signed(pkcs7)) {
            printf("not signed \n");
            ret = -3;
            break;
        }

        STACK_OF(X509)* certs = pkcs7->d.sign->cert;
        if (NULL == certs) {
            return -4;
        }

        X509* cert = sk_X509_pop(certs);  //aka sk_X509_value(certs, 0)
        if (NULL == cert) {
            return -5;
        }

        BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509_print(bio_out, cert);

        printf("%s\n", thumbprint(cert).c_str());

        STACK_OF(PKCS7_SIGNER_INFO)* infos = PKCS7_get_signer_info(pkcs7);
        digest(0, pkcs7);

        PKCS7_SIGNER_INFO* info = sk_PKCS7_SIGNER_INFO_pop(infos);
        //printf("%d\n", EVP_PKEY_type(OBJ_obj2nid(info->digest_alg->algorithm)));
        //to get type obj_mac.h
        //NID_rsaEncryption
        //
        printf("%d\n", (OBJ_obj2nid(info->digest_alg->algorithm)));
        printf("%d\n", (OBJ_obj2nid(info->digest_enc_alg->algorithm)));
        X509_signature_print(bio_out, info->digest_alg, NULL);
        X509_signature_print(bio_out, info->digest_enc_alg, NULL);

    } while(0);

    BIO_free(bio);
    return ret;
}

int main(int argc, char const *argv[])
{
    /* code */

    ParseAnroidCer("ANDROIDR.RSA", NULL, 0);
    return 0;
}
