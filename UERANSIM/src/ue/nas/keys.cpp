//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "keys.hpp"
#include <lib/crypt/crypt.hpp>
#include <stdexcept>

#include <iostream> // pastikan ini ada di bagian atas

static const int N_NAS_enc_alg = 0x01;
static const int N_NAS_int_alg = 0x02;
static const int N_RRC_enc_alg = 0x03;
static const int N_RRC_int_alg = 0x04;
static const int N_UP_enc_alg = 0x05;
static const int N_UP_int_alg = 0x06;

//tahap-9 //Prime-FS
extern "C" {
    #include "ext/compact25519/compact_x25519.h"
    }
#include <cstring>
//end

//tahap-10 //HPQC
extern "C" {
    #include "ext/mlkem/mlkem_wrapper.h"
    }
//end

namespace nr::ue::keys
{

void DeriveKeysSeafAmf(const UeConfig &ueConfig, const Plmn &currentPlmn, NasSecurityContext &nasSecurityContext)
{
    auto &keys = nasSecurityContext.keys;
    std::string snn = ConstructServingNetworkName(currentPlmn);

    OctetString s1[1];
    s1[0] = crypto::EncodeKdfString(snn);

    OctetString s2[2];
    s2[0] = crypto::EncodeKdfString(ueConfig.supi->value);
    s2[1] = keys.abba.copy();

    keys.kSeaf = crypto::CalculateKdfKey(keys.kAusf, 0x6C, s1, 1);
    keys.kAmf = crypto::CalculateKdfKey(keys.kSeaf, 0x6D, s2, 2);

    std::cout << "===========================DEBUG PARAMETER KDF================================ " << std::endl;
    std::cout << "[KDF DEBUG] SNN           = " << snn << std::endl;
    std::cout << "[KDF DEBUG] SUPI          = " << ueConfig.supi->value << std::endl;
    std::cout << "[KDF DEBUG] ABBA len      = " << keys.abba.length() << std::endl;
    std::cout << "[KDF DEBUG] ABBA value    = " << keys.abba.toHexString() << std::endl;
    std::cout << "[KDF DEBUG] KAUSF         = " << keys.kAusf.toHexString() << std::endl;
    std::cout << "[KDF DEBUG] KSEAF         = " << keys.kSeaf.toHexString() << std::endl;
    std::cout << "[KDF DEBUG] KAMF          = " << keys.kAmf.toHexString() << std::endl;
    std::cout << "===========================DEBUG PARAMETER KDF================================ " << std::endl;
}

void DeriveNasKeys(NasSecurityContext &securityContext)
{
    OctetString s1[2];
    s1[0] = OctetString::FromOctet(N_NAS_enc_alg);
    s1[1] = OctetString::FromOctet((int)securityContext.ciphering);

    OctetString s2[2];
    s2[0] = OctetString::FromOctet(N_NAS_int_alg);
    s2[1] = OctetString::FromOctet((int)securityContext.integrity);

    auto kdfEnc = crypto::CalculateKdfKey(securityContext.keys.kAmf, 0x69, s1, 2);
    auto kdfInt = crypto::CalculateKdfKey(securityContext.keys.kAmf, 0x69, s2, 2);

    securityContext.keys.kNasEnc = kdfEnc.subCopy(16, 16);
    securityContext.keys.kNasInt = kdfInt.subCopy(16, 16);
    std::cout << "[KDF DEBUG] KNASenc = " << securityContext.keys.kNasEnc.toHexString() << std::endl;
    std::cout << "[KDF DEBUG] KNASint = " << securityContext.keys.kNasInt.toHexString() << std::endl;
}

std::string ConstructServingNetworkName(const Plmn &plmn)
{
    char buffer[40] = {0};
    int r = sprintf(buffer, "5G:mnc%03d.mcc%03d.3gppnetwork.org", plmn.mnc, plmn.mcc);
    if (r != 32)
        throw std::runtime_error("SNN construction failure");
    return std::string{buffer};
}

OctetString CalculateKAusfFor5gAka(const OctetString &ck, const OctetString &ik, const std::string &snn,
                                   const OctetString &sqnXorAk)
{
    OctetString key = OctetString::Concat(ck, ik);
    OctetString s[2];
    s[0] = crypto::EncodeKdfString(snn);
    s[1] = sqnXorAk.copy();
    return crypto::CalculateKdfKey(key, 0x6A, s, 2);
}

std::pair<OctetString, OctetString> CalculateCkPrimeIkPrime(const OctetString &ck, const OctetString &ik,
                                                            const std::string &snn, const OctetString &sqnXorAk)
{
    std::cout << "[CK'] CK: " << ck.toHexString() << std::endl;
    std::cout << "[IK'] IK: " << ik.toHexString() << std::endl;
    std::cout << "[CK'] SNN: " << snn << std::endl;
    std::cout << "[CK'] SQN xor AK: " << sqnXorAk.toHexString() << std::endl;

    OctetString key = OctetString::Concat(ck, ik);

    std::cout << "[CK'] KDF Key (CK||IK): " << key.toHexString() << std::endl;

    OctetString s[2];
    s[0] = crypto::EncodeKdfString(snn);
    s[1] = sqnXorAk.copy();

    std::cout << "[CK'] KDF Input[0] (SNN Encoded): " << s[0].toHexString() << std::endl;
    std::cout << "[CK'] KDF Input[1] (SQN xor AK): " << s[1].toHexString() << std::endl;

    auto res = crypto::CalculateKdfKey(key, 0x20, s, 2);

    std::cout << "[CK'] KDF Output (CK' || IK'): " << res.toHexString() << std::endl;

    std::pair<OctetString, OctetString> ckIk;
    ckIk.first = res.subCopy(0, ck.length());
    ckIk.second = res.subCopy(ck.length());

    std::cout << "[CK'] CK': " << ckIk.first.toHexString() << std::endl;
    std::cout << "[IK'] IK': " << ckIk.second.toHexString() << std::endl;

    return ckIk;
}

OctetString CalculateMk(const OctetString &ckPrime, const OctetString &ikPrime, const Supi &supiIdentity)
{
    OctetString key = OctetString::Concat(ikPrime, ckPrime);
    OctetString input = OctetString::FromAscii("EAP-AKA'" + supiIdentity.value);

    std::cout << "[MK] SUPI used for PRF input: " << supiIdentity.value << std::endl;
    // std::cout << "[MK] Full Identity with prefix: " << fullIdentity << std::endl;
    std::cout << "[MK] PRF input string: " << input.toHexString() << std::endl;
    std::cout << "[MK] Key (IK'||CK') for PRF: " << key.toHexString() << std::endl;

    // Calculating the 208-octet output
    return crypto::CalculatePrfPrime(key, input, 208);
}

//tahap-9 //Prime-FS

static void cobahmac()
{
    // Sample Key 64 bytes
    std::vector<uint8_t> key = {
        0xAB, 0xD7, 0xF4, 0x41, 0x4F, 0x11, 0x4D, 0x99,
        0x63, 0xFF, 0xAD, 0x1F, 0xEB, 0x34, 0x5B, 0xB2,
        0x93, 0xA4, 0xCE, 0x59, 0x7E, 0x78, 0xA9, 0x77,
        0xAC, 0x7A, 0x28, 0x13, 0x4F, 0x9E, 0xAA, 0x9D,
        0x43, 0xE9, 0x3A, 0x3B, 0x1B, 0x73, 0xD2, 0x19,
        0x8E, 0xB7, 0x6D, 0xF7, 0xCE, 0x71, 0x77, 0x45,
        0x3F, 0xEB, 0xF0, 0xE5, 0xC9, 0x17, 0x69, 0xC7,
        0x9C, 0x67, 0xDA, 0x7C, 0x4B, 0xFE, 0x82, 0x5A
    };

    // Sample Input 27 bytes
    std::vector<uint8_t> input = {
        0x45, 0x41, 0x50, 0x2D, 0x41, 0x4B, 0x41, 0x27,
        0x20, 0x46, 0x53, 0x39, 0x39, 0x39, 0x37, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x31, 0x01   // <=== ini penting, harus 0x01!
    };

    OctetString key_octet{std::move(key)};
    OctetString input_octet{std::move(input)};

    auto mac_octet = crypto::HmacSha256(key_octet, input_octet);

    // Cetak semua
    std::cout << "cobahmac Key: " << key_octet.toHexString() << std::endl;
    std::cout << "cobahmac Input: " << input_octet.toHexString() << std::endl;
    std::cout << "cobahmac HMAC Output: " << mac_octet.toHexString() << std::endl;
}

OctetString CalculateMkFs(const OctetString &ikPrime, const OctetString &ckPrime,
    const OctetString &sharedSecret, const Supi &supi)
{
    // Ambil hanya 16 byte pertama dari shared secret
    auto shared32 = sharedSecret.subCopy(0, 32);
    auto key = OctetString::Concat(OctetString::Concat(ikPrime, ckPrime), shared32);  // 48 bytes
    // auto key = sharedSecret.subCopy(0, 32); // 32 bytes

    auto input = OctetString::FromAscii("EAP-AKA' FS" + supi.value);

    std::cout << "[MK_FS] Raw PRF Key Input: " << key.toHexString() << std::endl;
    std::cout << "[MK_FS] ogs_kdf_prf_prime_fs PRF Input (Label||SUPI): " << input.toHexString() << std::endl;

    cobahmac();

    return crypto::CalculatePrfPrime(key, input, 208);
    // return crypto::CalculatePrfPrimeFS(key, input, 208);
    // return crypto::CalculatePrfPrime(key, input, 208);
}



OctetString CalculateMkFsEquivalent(
    const OctetString &ikPrime,
    const OctetString &ckPrime,
    const OctetString &sharedSecret,
    const std::string &identity)
{
    //coba 48 byte [GAGAL]
    // uint8_t key[48];
    // memcpy(key, ikPrime.data(), 16);
    // memcpy(key + 16, ckPrime.data(), 16);
    // memcpy(key + 32, sharedSecret.data(), 16); // Only first 16 bytes

    //coba 32 byte [SUCCESS]
    uint8_t key[32];
    memcpy(key, sharedSecret.data(), 32);

    //coba 64 byte
    // uint8_t key[64];
    // memcpy(key, ikPrime.data(), 16);
    // memcpy(key + 16, ckPrime.data(), 16);
    // memcpy(key + 32, sharedSecret.data(), 32); // Only first 32 bytes

    // === Print KEY ===
    // std::cout << "[MK_FS] ogs_kdf_prf_prime_fs PRF KEY (IK'||CK'||SharedSecret_32): ";
    // for (size_t i = 0; i < 32; ++i)
    //     std::printf("%02X", key[i]);
    // std::cout << std::endl;

    const std::string label = "EAP-AKA' FS";
    const std::string labelAndIdentity = label + identity;
    std::vector<uint8_t> inputVec(labelAndIdentity.begin(), labelAndIdentity.end());
    const uint8_t *input = inputVec.data();
    size_t input_len = inputVec.size();

    // std::cout << "[MK_FS] PRF Input (Label||SUPI): ";
    // for (size_t i = 0; i < input_len; ++i)
    //     std::printf("%02X", input[i]);
    // std::cout << std::endl;

    const size_t HMAC_OUTPUT_LEN = 32;
    const size_t MK_LEN = 208;
    uint8_t T_prev[HMAC_OUTPUT_LEN] = {0};
    size_t offset = 0;
    uint8_t round = 1;
    std::vector<uint8_t> mk(MK_LEN);

    while (offset < MK_LEN) {
        std::vector<uint8_t> buf;

        if (round == 1) {
            buf.insert(buf.end(), input, input + input_len);
            buf.push_back(round);

            // std::cout << "[ROUND-1 BUFFER] ";
            // for (auto b : buf) std::printf("%02X", b);
            // std::cout << std::endl;

        } else {
            buf.insert(buf.end(), T_prev, T_prev + HMAC_OUTPUT_LEN);
            buf.insert(buf.end(), input, input + input_len);
            buf.push_back(round);
        }

        // std::cout << "[PRF-Round " << int(round) << "] Buffer: ";
        // for (auto b : buf) std::printf("%02X", b);
        // std::cout << std::endl;

        OctetString hmacResult = crypto::HmacSha256(
            OctetString::FromArray(key, sizeof(key)),
            OctetString::FromArray(buf.data(), buf.size()));

        // if (round == 1) {
        //     std::cout << "[ROUND-1 T_prev (HMAC)] ";
        //     for (size_t i = 0; i < HMAC_OUTPUT_LEN; ++i)
        //         std::printf("%02X", hmacResult.data()[i]);
        //     std::cout << std::endl;
        // }

        memcpy(T_prev, hmacResult.data(), HMAC_OUTPUT_LEN);

        size_t copy_len = std::min(HMAC_OUTPUT_LEN, MK_LEN - offset);
        memcpy(mk.data() + offset, T_prev, copy_len);
        offset += copy_len;
        round++;
    }

    return OctetString::FromArray(mk.data(), mk.size());
}


OctetString CalculateX25519SharedSecret(const OctetString &privKey, const OctetString &pubKey)
{
    uint8_t shared[32];
    uint8_t privateKey[32];

    memcpy(privateKey, privKey.data(), 32);

    std::cout << "UE Private Key (original): " << privKey.toHexString() << std::endl;
    std::cout << "Peer Public Key (received): " << pubKey.toHexString() << std::endl;

    compact_x25519_shared(shared, privateKey, pubKey.data());

    OctetString result = OctetString::FromArray(shared, 32);
    std::cout << "Shared Secret             : " << result.toHexString() << std::endl;

    return result;
}

OctetString CalculateKAusfForEapAkaPrimeFs(const OctetString &mkEcdhe)
{
    // Pastikan panjang MK_ECDHE cukup (harus minimal 160 byte)
    if (mkEcdhe.length() < 160)
        throw std::runtime_error("MK_ECDHE is too short for extracting K_AUSF from EMSK");

    // EMSK dimulai dari offset 96
    auto emsk = mkEcdhe.subCopy(96, 64);

    // K_AUSF = 32 byte pertama dari EMSK
    return emsk.subCopy(0, 32);
}
OctetString CalculateKAusfForEapAkaPrimeFsHPQC(const OctetString &mkEcdhe)
{
    // Pastikan panjang MK_HYBRID cukup (harus minimal 160 byte)
    if (mkEcdhe.length() < 160)
        throw std::runtime_error("MK_HYBRID is too short for extracting K_AUSF from EMSK");

    // EMSK dimulai dari offset 96
    auto emsk = mkEcdhe.subCopy(96, 64);

    // K_AUSF = 32 byte pertama dari EMSK
    return emsk.subCopy(0, 32);
}

//end

//tahap-10
bool MlkemEncapsulate(const OctetString &pkM, uint8_t *ct, uint8_t *ss)
{
    if (pkM.length() != 1184) {
        std::cout << "[MlkemEncapsulate] Invalid ML-KEM public key length: " << pkM.length() << std::endl;
        return false;
    }

    mlkem_encapsulate(pkM.data(), ct, ss);
    return true;
}
//end


OctetString CalculateMacForEapAkaPrime(const OctetString &kaut, const eap::EapAkaPrime &message)
{


    // Create a copy of the EAP message
    eap::EapAkaPrime copy{message.code, message.id, message.subType};

    // Deep copy each attribute
    // message.attributes.forEachEntryOrdered(
    //     [&copy](eap::EAttributeType attr, const OctetString &v) { copy.attributes.putRawAttribute(attr, v.copy()); });

    message.attributes.forEachEntryOrdered(
        [&copy](eap::EAttributeType attr, const OctetString &v) {
            std::cout << "[ATTR] Type=0x" << std::hex << (int)attr
                      << ", Length=" << std::dec << v.length() << std::endl;
    
            if (attr == eap::EAttributeType::AT_PUB_HYBRID) {
                // Special handling: adjust so EncodeEapPdu later uses 2-byte length
                // This assumes you added an overload or method in EapAttributes to handle this flag
                copy.attributes.putRawAttributeWith2ByteLength(attr, v.copy()); // hypothetical
            } else {
                copy.attributes.putRawAttribute(attr, v.copy());
            }
        });
    

    // Except the MAC field
    copy.attributes.replaceMac(OctetString::FromSpare(16));

    OctetString input{};
    eap::EncodeEapPdu(input, copy);

    auto sha = crypto::HmacSha256(kaut, input);
    
    std::cout << "[MAC] K_AUT: " << kaut.toHexString() << std::endl;
    std::cout << "[MAC] Calculated MAC: " << sha.subCopy(0,16).toHexString() << std::endl;

    return sha.subCopy(0, 16);
}

OctetString CalculateKAusfForEapAkaPrime(const OctetString &mk)
{
    // Octets [144...207] are EMSK
    auto emsk = mk.subCopy(144);
    // The most significant 256 bits of EMSK is K_AUSF
    return emsk.subCopy(0, 32);
}

OctetString CalculateResStar(const OctetString &key, const std::string &snn, const OctetString &rand,
                             const OctetString &res)
{
    OctetString params[3];
    params[0] = crypto::EncodeKdfString(snn);
    params[1] = rand.copy();
    params[2] = res.copy();

    auto output = crypto::CalculateKdfKey(key, 0x6B, params, 3);

    // The (X)RES* is identified with the 128 least significant bits of the output of the KDF.
    return output.subCopy(output.length() - 16);
}

OctetString DeriveAmfPrimeInMobility(bool isUplink, const NasCount &count, const OctetString &kAmf)
{
    OctetString params[2];
    params[0] = OctetString::FromOctet(isUplink ? 0x00 : 0x01);
    params[1] = OctetString::FromOctet4(count.toOctet4());

    return crypto::CalculateKdfKey(kAmf, 0x72, params, 2);
}

OctetString CalculateAuts(const OctetString &sqn, const OctetString &ak, const OctetString &macS)
{
    OctetString auts = OctetString::Xor(sqn, ak);
    auts.append(macS);
    return auts;
}

} // namespace nr::ue::keys