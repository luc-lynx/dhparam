#include <iostream>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/pem.h>


int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "DH.P must be the first parameter" << std::endl;
        std::cerr << "DH.G must be the second parameter" << std::endl;
        return 1;
    }

    std::string dhp = std::string(argv[1]);
    std::string dhg = std::string(argv[2]);

    std::cerr << "[>] Got DH.P " << dhp << std::endl;
    std::cerr << "[>] Got DH.G " << dhg << std::endl;

    BIGNUM *p = BN_new();
    int err = BN_dec2bn(&p, dhp.c_str());
    if (err == 0) {
        BN_free(p);
        std::cerr << "[E] BN_dec2bn returned error (p)" << std::endl;
        return 1;
    }

    BIGNUM *g = BN_new();
    err = BN_dec2bn(&g, dhg.c_str());
    if (err == 0) {
        BN_free(p);
        BN_free(g);
        std::cerr << "[E] BN_dec2bn returned error (g)" << std::endl;
        return 1;
    }

    DH *dh = DH_new();

    dh->p = p;
    dh->g = g;

    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        DH_free(dh);
        std::cerr << "[E] Can't open stdout" << std::endl;
        return 1;
    }

    PEM_write_bio_DHparams(out, dh);
    BIO_flush(out);
    BIO_free(out);
    DH_free(dh);

    return 0;
}