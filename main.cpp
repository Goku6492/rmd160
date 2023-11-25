// main.cpp
#include <iostream>
#include <fstream>
#include <iomanip>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

const std::string TARGET_RMD = "61eb8a50c86b0584bb727dd65bed8d2400d6d5aa";

std::string generateRandomHexPrivateKey() {
    // Specify the range of private keys
    const std::string lower_limit = "11111112e2b7899ec0";
    const std::string upper_limit = "1feff0000000000000";

    // Convert hex strings to integers
    unsigned long long lower = std::stoull(lower_limit, nullptr, 16);
    unsigned long long upper = std::stoull(upper_limit, nullptr, 16);

    // Generate a random private key within the specified range
    unsigned long long random_value = (RAND_MAX * rand() + rand()) % (upper - lower + 1) + lower;

    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(20) << random_value;
    return ss.str();
}

std::string privateKeyToCompressedPublicKey(const std::string &private_key_hex) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        std::cerr << "Error creating EC key" << std::endl;
        exit(EXIT_FAILURE);
    }

    BIGNUM *priv_key_bn = BN_new();
    BN_hex2bn(&priv_key_bn, private_key_hex.c_str());
    EC_KEY_set_private_key(eckey, priv_key_bn);

    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(eckey);
    if (!pub_key_point) {
        std::cerr << "Error extracting public key point" << std::endl;
        exit(EXIT_FAILURE);
    }

    unsigned char *compressed_pub_key = NULL;
    size_t compressed_pub_key_len = EC_POINT_point2buf(
        EC_KEY_get0_group(eckey),
        pub_key_point,
        POINT_CONVERSION_COMPRESSED,
        &compressed_pub_key,
        NULL
    );

    std::string compressed_pub_key_hex(
        compressed_pub_key,
        compressed_pub_key + compressed_pub_key_len
    );

    OPENSSL_free(compressed_pub_key);
    BN_free(priv_key_bn);
    EC_KEY_free(eckey);

    return compressed_pub_key_hex;
}

std::string ripemd160(const std::string &input) {
    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(reinterpret_cast<const unsigned char *>(input.c_str()), input.length(), hash);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto &byte : hash) {
        ss << std::setw(2) << static_cast<unsigned>(byte);
    }

    return ss.str();
}

void searchTargetRMD(const std::string &target_rmd, const std::string &private_key) {
    std::string compressed_pub_key = privateKeyToCompressedPublicKey(private_key);
    std::string current_rmd = ripemd160(compressed_pub_key);

    if (current_rmd.substr(0, 8) == "61eb8a5") {
        std::cout << "RMD: " << current_rmd << "\n";
        std::cout << "Public Key: " << compressed_pub_key << "\n\n";

        std::ofstream outfile("rmdfound.txt", std::ios::app);
        if (outfile.is_open()) {
            outfile << "RMD: " << current_rmd << "\n";
            outfile << "Public Key: " << compressed_pub_key << "\n\n";
            outfile.close();
        } else {
            std::cerr << "Error opening output file" << std::endl;
        }
    }
}

int main() {
    const std::string target_rmd_prefix = TARGET_RMD.substr(0, 8);

    std::cout << "Searching for target RMD: " << TARGET_RMD << "\n";

    for (int i = 0; i < 1000000; ++i) {
        std::string private_key = generateRandomHexPrivateKey();
        searchTargetRMD(TARGET_RMD, private_key);

        if (i % 10000 == 0) {
            double progress = static_cast<double>(i) / 1000000.0 * 100.0;
            std::cout << "\rProgress: " << std::fixed << std::setprecision(2) << progress << "%";
            std::cout.flush();
        }
    }

    std::cout << "\nSearch complete.\n";

    return 0;
}
