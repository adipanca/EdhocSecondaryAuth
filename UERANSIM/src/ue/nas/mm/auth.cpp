//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "mm.hpp"

#include <lib/nas/utils.hpp>
#include <ue/nas/keys.hpp>

//tahap-9 //Prime-FS
extern "C" {
    #include "ext/compact25519/c25519/c25519.h"
}
#include <cstring>  // Tambahkan ini di bagian atas
//end

namespace nr::ue
{

void NasMm::receiveAuthenticationRequest(const nas::AuthenticationRequest &msg)
{
    m_logger->debug("Authentication Request received");

    if (!m_usim->isValid())
    {
        m_logger->warn("Authentication request is ignored. USIM is invalid");
        return;
    }

    m_timers->t3520.start();

    if (msg.eapMessage.has_value())
        receiveAuthenticationRequestEap(msg);
    else
        receiveAuthenticationRequest5gAka(msg);
}

void NasMm::receiveAuthenticationRequestEap(const nas::AuthenticationRequest &msg)
{
    m_logger->info("Apakah Masuk SINI? receiveAuthenticationRequestEap");
    Plmn currentPlmn = m_base->shCtx.getCurrentPlmn();
    if (!currentPlmn.hasValue())
        return;

    auto sendEapFailure = [this](std::unique_ptr<eap::Eap> &&eap) {
        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        nas::AuthenticationResponse resp;
        resp.eapMessage = nas::IEEapMessage{};
        resp.eapMessage->eap = std::move(eap);
        sendNasMessage(resp);
    };

    auto sendAuthFailure = [this](nas::EMmCause cause) {
        m_logger->err("Sending Authentication Failure with cause [%s]", nas::utils::EnumToString(cause));

        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        // Send Authentication Failure
        nas::AuthenticationFailure resp{};
        resp.mmCause.value = cause;
        sendNasMessage(resp);
    };

    // ========================== Check the received message syntactically ==========================

    if (!msg.eapMessage.has_value() || !msg.eapMessage->eap)
    {
        m_logger->err("Apakah Masuk SINI? if (!msg.eapMessage.has_value() || !msg.eapMessage->eap)");
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    if (msg.eapMessage->eap->eapType != eap::EEapType::EAP_AKA_PRIME)
    {
        m_logger->err("Apakah Masuk SINI? if (msg.eapMessage->eap->eapType != eap::EEapType::EAP_AKA_PRIME)");
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    auto &receivedEap = (const eap::EapAkaPrime &)*msg.eapMessage->eap;

    if (receivedEap.subType != eap::ESubType::AKA_CHALLENGE)
    {
        m_logger->err("Apakah Masuk SINI? if (receivedEap.subType != eap::ESubType::AKA_CHALLENGE)");
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // ================================ Check the received parameters syntactically ================================

    auto receivedRand = receivedEap.attributes.getRand();
    auto receivedMac = receivedEap.attributes.getMac();
    auto receivedAutn = receivedEap.attributes.getAutn();

    if (receivedRand.length() != 16 || receivedAutn.length() != 16 || receivedMac.length() != 16)
    {
        m_logger->err("Apakah Masuk SINI? if (receivedRand.length() != 16 || receivedAutn.length() != 16 || receivedMac.length() != 16)");
        sendMmStatus(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // =================================== Check the received KDF and KDF_INPUT ===================================

    if (receivedEap.attributes.getKdf() != 1)
    {
        m_logger->err("EAP AKA' Authentication Reject, received AT_KDF is not valid");
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
        return;
    }

    auto snn = keys::ConstructServingNetworkName(currentPlmn);

    if (receivedEap.attributes.getKdfInput() != OctetString::FromAscii(snn))
    {
        m_logger->err("EAP AKA' Authentication Reject, received AT_KDF_INPUT is not valid");

        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
        return;
    }

    // =================================== Check the received ngKSI ===================================

    if (msg.ngKSI.tsc == nas::ETypeOfSecurityContext::MAPPED_SECURITY_CONTEXT)
    {
        m_logger->err("Mapped security context not supported");
        sendAuthFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if (msg.ngKSI.ksi == nas::IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED)
    {
        m_logger->err("Invalid ngKSI value received");
        sendAuthFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if ((m_usim->m_currentNsCtx && m_usim->m_currentNsCtx->ngKsi == msg.ngKSI.ksi) ||
        (m_usim->m_nonCurrentNsCtx && m_usim->m_nonCurrentNsCtx->ngKsi == msg.ngKSI.ksi))
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();
        sendAuthFailure(nas::EMmCause::NGKSI_ALREADY_IN_USE);
        return;
    }

    // =================================== Check the received AUTN ===================================

    auto autnCheck = validateAutn(receivedRand, receivedAutn);
    m_timers->t3516.start();

    if (autnCheck == EAutnValidationRes::OK)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), receivedRand, false);
        auto sqnXorAk = OctetString::Xor(m_usim->m_sqnMng->getSqn(), milenage.ak);
        auto ckPrimeIkPrime = keys::CalculateCkPrimeIkPrime(milenage.ck, milenage.ik, snn, sqnXorAk);
        auto &ckPrime = ckPrimeIkPrime.first;
        auto &ikPrime = ckPrimeIkPrime.second;

        //tahap-9 //Prime-FS
        OctetString mk_ecdhe; 
        auto receivedPubEcdhe = receivedEap.attributes.getAttribute(eap::EAttributeType::AT_PUB_ECDHE);
        auto receivedKdfFs = receivedEap.attributes.getAttribute(eap::EAttributeType::AT_KDF_FS);

        m_logger->info("Detected EAP-AKA' FS mode, received UE Pub ECDHE = %s",
            receivedPubEcdhe.toHexString().c_str());

        m_logger->info("Detected EAP-AKA' FS mode, received UE KDF FS = %s",
            receivedKdfFs.toHexString().c_str());

        bool isFs = (receivedPubEcdhe.length() > 0 &&
            receivedKdfFs.length() >= 1 &&
            receivedKdfFs.data()[0] == 1); // 1 = FS KDF ID (misalnya X25519)


        if (isFs) {
            m_logger->info("Detected EAP-AKA' FS mode, received UE Pub ECDHE = %s && UE KDF FS = %s",
                           receivedPubEcdhe.toHexString().c_str(),receivedKdfFs.toHexString().c_str());
        
            uint8_t priv[32], pub[32];
            uint8_t basepoint[32] = {9};
            
            c25519_prepare(priv);                    // generate private key
            c25519_smult(pub, basepoint, priv);      // derive public key from basepoint
            
            OctetString uePrivateKey(std::vector<uint8_t>(priv, priv + 32));
            OctetString pubEcdhe(std::vector<uint8_t>(pub, pub + 32));
            
            m_usim->m_eccPrivKey = uePrivateKey.copy();
            m_usim->m_eccPubKey = pubEcdhe.copy();
            
            m_logger->info("Generated UE Private Key (X25519): %s", uePrivateKey.toHexString().c_str());
            m_logger->info("Generated UE Public  Key (X25519): %s", pubEcdhe.toHexString().c_str());

            // Asumsikan receivedPubEcdhe adalah OctetString 36-byte (dari AT_PUB_ECDHE Open5GS)
            auto pubEcdheOnly = receivedPubEcdhe.subCopy(2);  // Skip reserved

            m_logger->info("received UE Pub ECDHE without RESERVED FS = %s",pubEcdheOnly.toHexString().c_str());
            
            // Hitung shared secret
            auto sharedSecret = keys::CalculateX25519SharedSecret(uePrivateKey, pubEcdheOnly);

            m_logger->info("Shared Secret: %s", sharedSecret.toHexString().c_str());
        
            // Derive MK pakai FS logic (X25519 shared secret)
            // UERANSIM
            m_logger->info("============================== PRINT PARAMETER UERANSIM ============================= ");
            m_logger->info("IK': %s", ikPrime.toHexString().c_str());
            m_logger->info("CK': %s", ckPrime.toHexString().c_str());
            m_logger->info("Shared Secret: %s", sharedSecret.toHexString().c_str());
            const std::string &fullSupi = m_base->config->supi.value().value;
            std::string identity = fullSupi.substr(5);
            m_logger->info("SUPI (full)         : %s", fullSupi.c_str());
            m_logger->info("SUPI for PRF (no imsi-): %s", identity.c_str());
            m_logger->info("============================== PRINT PARAMETER UERANSIM ============================= ");

            mk_ecdhe = keys::CalculateMkFs(ikPrime, ckPrime, sharedSecret, m_base->config->supi.value());
            // mk_ecdhe = keys::CalculateMkFsEquivalent(ikPrime, ckPrime, sharedSecret, m_base->config->supi.value().value);
            m_logger->info("MK _ECDHE = %s", mk_ecdhe.toHexString().c_str());
        }
        //end

        //tahap-10 //HPQC
        auto receivedPubHybrid = receivedEap.attributes.getAttribute(eap::EAttributeType::AT_PUB_HYBRID);
        auto receivedKdfFsHybrid = receivedEap.attributes.getAttribute(eap::EAttributeType::AT_KDF_FS);

        m_logger->info("Detected EAP-AKA' HYBRID mode, received UE Pub HYBRID = %s",
            receivedPubHybrid.toHexString().c_str());
        m_logger->info("Detected EAP-AKA' HYBRID mode, received UE KDF FS = %s",
            receivedKdfFsHybrid.toHexString().c_str());
        
        bool isHPQC = (receivedPubHybrid.length() > 0 &&
        receivedKdfFsHybrid.length() >= 1 &&
        receivedKdfFsHybrid.data()[0] == 1); 
        
        OctetString mk_Hybrid;

        if (isHPQC) {
            const auto &pubHybridValue = receivedPubHybrid;
            OctetString receivedPkM = pubHybridValue.subCopy(1, 1184); //hilangkan 1 reserved
            OctetString receivedPkX = pubHybridValue.subCopy(1185, 32); //hilangkan 1 reserved OK

            uint8_t priv_X25519[32], pub_X25519[32];
            uint8_t basepoint_X25519[32] = {9};
        
            // lanjut encapsulate setelah ini
            c25519_prepare(priv_X25519);                    // generate private key
            c25519_smult(pub_X25519, basepoint_X25519, priv_X25519);      // derive public key from basepoint
            
            OctetString uePrivateKey(std::vector<uint8_t>(priv_X25519, priv_X25519 + 32));
            OctetString pubEcdhe(std::vector<uint8_t>(pub_X25519, pub_X25519 + 32));
            
            m_usim->m_eccPrivKey = uePrivateKey.copy();
            m_usim->m_eccPubKey = pubEcdhe.copy();
            
            m_logger->info("Generated UE Private Key (X25519) HPQC: %s", uePrivateKey.toHexString().c_str());
            m_logger->info("Generated UE Public  Key (X25519) HPQC: %s", pubEcdhe.toHexString().c_str());


            m_logger->info("received UE Pub ML-KEM without RESERVED HPQC = %s",receivedPkM.toHexString().c_str());

            // Encapsulate pk_M
            uint8_t ctM[OGS_MLKEM_CIPHERTEXT_SIZE] = {0};
            uint8_t ssM[OGS_MLKEM_SHARED_SECRET_SIZE] = {0};
            if (!keys::MlkemEncapsulate(receivedPkM, ctM, ssM)) {
                m_logger->err("Failed ML-KEM encapsulation");
            }

            // Setelah sukses encapsulate
            m_usim->m_mlkemCiphertext = OctetString(std::vector<uint8_t>(ctM, ctM + OGS_MLKEM_CIPHERTEXT_SIZE));

            // Asumsikan receivedPkX adalah OctetString 36-byte (dari AT_PUB_ECDHE Open5GS)
            // auto pubEcdheOnly_X25519 = receivedPkX.subCopy(2);  // Skip reserved
            OctetString pubEcdheOnly_X25519 = receivedPkX.copy(); //no reserved

            m_logger->info("received UE Pub ECDHE without RESERVED HPQC = %s",pubEcdheOnly_X25519.toHexString().c_str());
            
            // Hitung shared secret
            auto sharedSecret_X25519 = keys::CalculateX25519SharedSecret(uePrivateKey, pubEcdheOnly_X25519);

            m_logger->info("Shared Secret: %s", sharedSecret_X25519.toHexString().c_str());

             // Combine hybrid shared secret
            OctetString hybridSharedSecret;
            OctetString sharedSecretM(std::vector<uint8_t>(ssM, ssM + sizeof(ssM)));
            hybridSharedSecret.append(sharedSecretM);
            hybridSharedSecret.append(sharedSecret_X25519);
            m_logger->info("Hybrid Shared Secret (ML-KEM + X25519): %s", hybridSharedSecret.toHexString().c_str());

            // Derive MK pakai FS logic (X25519 shared secret)
            // UERANSIM
            m_logger->info("============================== PRINT PARAMETER UERANSIM ============================= ");
            m_logger->info("IK': %s", ikPrime.toHexString().c_str());
            m_logger->info("CK': %s", ckPrime.toHexString().c_str());
            m_logger->info("HYBRID Shared Secret: %s", sharedSecret_X25519.toHexString().c_str());
            const std::string &fullSupi = m_base->config->supi.value().value;
            std::string identity = fullSupi.substr(5);
            m_logger->info("SUPI (full)         : %s", fullSupi.c_str());
            m_logger->info("SUPI for PRF (no imsi-): %s", identity.c_str());
            m_logger->info("============================== PRINT PARAMETER UERANSIM ============================= ");

            // mk_Hybrid = keys::CalculateMkFsEquivalent(ikPrime, ckPrime, hybridSharedSecret, m_base->config->supi.value().value);
            mk_Hybrid  = keys::CalculateMkFs(ikPrime, ckPrime, hybridSharedSecret, m_base->config->supi.value());
            m_logger->info("MK _HYBRID= %s", mk_Hybrid.toHexString().c_str());
        }
        //end
        
        auto mk = keys::CalculateMk(ckPrime, ikPrime, m_base->config->supi.value());
        auto kaut = mk.subCopy(16, 32);

        m_logger->info("MK = %s", mk.toHexString().c_str());
        m_logger->info("K_AUT PRIME = %s", kaut.toHexString().c_str());

        // Check the received AT_MAC
        auto expectedMac = keys::CalculateMacForEapAkaPrime(kaut, receivedEap);
        if (expectedMac != receivedMac)
        {
            m_logger->err("AT_MAC failure in EAP AKA'. expected: %s received: %s", expectedMac.toHexString().c_str(),
                          receivedMac.toHexString().c_str());
            if (networkFailingTheAuthCheck(true))
                return;
            m_timers->t3520.start();

            auto eap = std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_CLIENT_ERROR);
            eap->attributes.putClientErrorCode(0);
            sendEapFailure(std::move(eap));
            return;
        }

        // Store the relevant parameters
        m_usim->m_rand = receivedRand.copy();
        m_usim->m_resStar = {};

        // Create new partial native NAS security context and continue with key derivation
        m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
        m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
        m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
        if(isFs){
            m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrimeFs(mk_ecdhe);
            m_logger->info("kAusf Success MK_ECDHE = %s", mk_ecdhe.toHexString().c_str());
        }else if(isHPQC){
            m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrimeFsHPQC(mk_Hybrid);
            m_logger->info("kAusf Success MK_HYBRID = %s", mk_Hybrid.toHexString().c_str());
        }else{
            m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfForEapAkaPrime(mk);
            m_logger->info("kAusf Success MK = %s", mk.toHexString().c_str());
        }
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

        keys::DeriveKeysSeafAmf(*m_base->config, currentPlmn, *m_usim->m_nonCurrentNsCtx);

        // Send response
        m_nwConsecutiveAuthFailure = 0;
        m_timers->t3520.stop();
        {
            auto *akaPrimeResponse =
                new eap::EapAkaPrime(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CHALLENGE);
            akaPrimeResponse->attributes.putRes(milenage.res);
            akaPrimeResponse->attributes.putMac(OctetString::FromSpare(16)); // Dummy mac
            akaPrimeResponse->attributes.putKdf(1);

            if (isFs) {
                // Ambil kembali public key dari langkah generate sebelumnya
                //tambahkan reserved
                // Tambahkan 4 byte reserved di depan public key
                std::vector<uint8_t> pubWithReserved(36, 0x00); // 36 byte, semua 0 dulu
                std::memcpy(pubWithReserved.data() + 4, m_usim->m_eccPubKey.data(), m_usim->m_eccPubKey.length());

                // Buat OctetString baru dari vector yang sudah digabung reserved
                OctetString pubEcdheWithReserved(std::move(pubWithReserved));

                // Masukkan ke dalam EAP Attribute
                akaPrimeResponse->attributes.putRawAttribute(eap::EAttributeType::AT_PUB_ECDHE, std::move(pubEcdheWithReserved));

                
                // Hapus private/public key setelah dipakai (optional, demi keamanan)
                m_usim->m_eccPrivKey = OctetString();
                m_usim->m_eccPubKey = OctetString();     

                m_logger->info("K_AUT PRIME FS = %s", kaut.toHexString().c_str());          
            }

            if (isHPQC) {
                OctetString ctHybrid;
            
                // Append ML-KEM ciphertext
                ctHybrid.append(m_usim->m_mlkemCiphertext);
                
                // Append UE ephemeral X25519 public key
                ctHybrid.append(m_usim->m_eccPubKey);
            
                // Masukkan ke EAP Response Attribute
                // akaPrimeResponse->attributes.putRawAttribute(eap::EAttributeType::AT_PUB_HYBRID, std::move(ctHybrid));
                akaPrimeResponse->attributes.putRawAttributeWith2ByteLength(eap::EAttributeType::AT_PUB_HYBRID, std::move(ctHybrid));
                
                // Hapus key ephemeral setelah pakai
                m_usim->m_eccPrivKey = OctetString();
                m_usim->m_eccPubKey = OctetString();
            
                m_logger->info("K_AUT PRIME FS HYBRID = %s", kaut.toHexString().c_str());
            }            

            // Calculate and put mac value
            auto sendingMac = keys::CalculateMacForEapAkaPrime(kaut, *akaPrimeResponse);
            akaPrimeResponse->attributes.replaceMac(sendingMac);

            nas::AuthenticationResponse resp;
            resp.eapMessage = nas::IEEapMessage{};
            resp.eapMessage->eap = std::unique_ptr<eap::EapAkaPrime>(akaPrimeResponse);

            m_logger->info("Sending EAP Response to AMF: EAP ID = %d", eap::ECode::RESPONSE);
            m_logger->debug("EAP Payload: %s", akaPrimeResponse->attributes.toString().c_str());

            sendNasMessage(resp);
        }
    }
    else if (autnCheck == EAutnValidationRes::MAC_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendEapFailure(std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                          eap::ESubType::AKA_AUTHENTICATION_REJECT));
    }
    else if (autnCheck == EAutnValidationRes::SYNCHRONISATION_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();

        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), receivedRand, true);
        auto auts = keys::CalculateAuts(m_usim->m_sqnMng->getSqn(), milenage.ak_r, milenage.mac_s);

        auto eap = std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id,
                                                      eap::ESubType::AKA_SYNCHRONIZATION_FAILURE);
        eap->attributes.putAuts(std::move(auts));
        sendEapFailure(std::move(eap));
    }
    else // the other case, separation bit mismatched
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();

        auto eap =
            std::make_unique<eap::EapAkaPrime>(eap::ECode::RESPONSE, receivedEap.id, eap::ESubType::AKA_CLIENT_ERROR);
        eap->attributes.putClientErrorCode(0);
        sendEapFailure(std::move(eap));
    }
}

void NasMm::receiveAuthenticationRequest5gAka(const nas::AuthenticationRequest &msg)
{
    Plmn currentPLmn = m_base->shCtx.getCurrentPlmn();
    if (!currentPLmn.hasValue())
        return;

    auto sendFailure = [this](nas::EMmCause cause, std::optional<OctetString> &&auts = std::nullopt) {
        if (cause != nas::EMmCause::SYNCH_FAILURE)
            m_logger->err("Sending Authentication Failure with cause [%s]", nas::utils::EnumToString(cause));
        else
            m_logger->debug("Sending Authentication Failure due to SQN out of range");

        // Clear RAND and RES* stored in volatile memory
        m_usim->m_rand = {};
        m_usim->m_resStar = {};

        // Stop T3516 if running
        m_timers->t3516.stop();

        // Send Authentication Failure
        nas::AuthenticationFailure resp{};
        resp.mmCause.value = cause;

        if (auts.has_value())
        {
            resp.authenticationFailureParameter = nas::IEAuthenticationFailureParameter{};
            resp.authenticationFailureParameter->rawData = std::move(*auts);
        }

        sendNasMessage(resp);
    };

    // ========================== Check the received parameters syntactically ==========================

    if (!msg.authParamRAND.has_value() || !msg.authParamAUTN.has_value())
    {
        m_logger->err("masuk sini IF(!msg.authParamRAND.has_value() || !msg.authParamAUTN.has_value())");
        sendFailure(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    if (msg.authParamRAND->value.length() != 16 || msg.authParamAUTN->value.length() != 16)
    {
        m_logger->err("masuk sini if (msg.authParamRAND->value.length() != 16 || msg.authParamAUTN->value.length() != 16)");
        sendFailure(nas::EMmCause::SEMANTICALLY_INCORRECT_MESSAGE);
        return;
    }

    // =================================== Check the received ngKSI ===================================

    if (msg.ngKSI.tsc == nas::ETypeOfSecurityContext::MAPPED_SECURITY_CONTEXT)
    {
        m_logger->err("Mapped security context not supported");
        sendFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if (msg.ngKSI.ksi == nas::IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED)
    {
        m_logger->err("Invalid ngKSI value received");
        sendFailure(nas::EMmCause::UNSPECIFIED_PROTOCOL_ERROR);
        return;
    }

    if ((m_usim->m_currentNsCtx && m_usim->m_currentNsCtx->ngKsi == msg.ngKSI.ksi) ||
        (m_usim->m_nonCurrentNsCtx && m_usim->m_nonCurrentNsCtx->ngKsi == msg.ngKSI.ksi))
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();
        sendFailure(nas::EMmCause::NGKSI_ALREADY_IN_USE);
        return;
    }

    // ============================================ Others ============================================

    auto &rand = msg.authParamRAND->value;
    auto &autn = msg.authParamAUTN->value;

    EAutnValidationRes autnCheck = EAutnValidationRes::OK;

    // If the received RAND is same with store stored RAND, bypass AUTN validation
    // NOTE: Not completely sure if this is correct and the spec meant this. But in worst case, synchronisation failure
    //  happens, and hopefully that can be restored with the normal resynchronization procedure.
    if (m_usim->m_rand != rand)
    {
        autnCheck = validateAutn(rand, autn);
        m_timers->t3516.start();
    }

    if (autnCheck == EAutnValidationRes::OK)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, false);
        auto ckIk = OctetString::Concat(milenage.ck, milenage.ik);
        auto sqnXorAk = OctetString::Xor(m_usim->m_sqnMng->getSqn(), milenage.ak);
        auto snn = keys::ConstructServingNetworkName(currentPLmn);

        // Store the relevant parameters
        m_usim->m_rand = rand.copy();
        m_usim->m_resStar = keys::CalculateResStar(ckIk, snn, rand, milenage.res);

        // Create new partial native NAS security context and continue with key derivation
        m_usim->m_nonCurrentNsCtx = std::make_unique<NasSecurityContext>();
        m_usim->m_nonCurrentNsCtx->tsc = msg.ngKSI.tsc;
        m_usim->m_nonCurrentNsCtx->ngKsi = msg.ngKSI.ksi;
        m_usim->m_nonCurrentNsCtx->keys.kAusf = keys::CalculateKAusfFor5gAka(milenage.ck, milenage.ik, snn, sqnXorAk);
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba.rawData.copy();

        keys::DeriveKeysSeafAmf(*m_base->config, currentPLmn, *m_usim->m_nonCurrentNsCtx);

        // Send response
        m_nwConsecutiveAuthFailure = 0;
        m_timers->t3520.stop();

        nas::AuthenticationResponse resp;
        resp.authenticationResponseParameter = nas::IEAuthenticationResponseParameter{};
        resp.authenticationResponseParameter->rawData = m_usim->m_resStar.copy();

        sendNasMessage(resp);
    }
    else if (autnCheck == EAutnValidationRes::MAC_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendFailure(nas::EMmCause::MAC_FAILURE);
    }
    else if (autnCheck == EAutnValidationRes::SYNCHRONISATION_FAILURE)
    {
        if (networkFailingTheAuthCheck(true))
            return;

        m_timers->t3520.start();

        auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, true);
        auto auts = keys::CalculateAuts(m_usim->m_sqnMng->getSqn(), milenage.ak_r, milenage.mac_s);
        sendFailure(nas::EMmCause::SYNCH_FAILURE, std::move(auts));
    }
    else // the other case, separation bit mismatched
    {
        if (networkFailingTheAuthCheck(true))
            return;
        m_timers->t3520.start();
        sendFailure(nas::EMmCause::NON_5G_AUTHENTICATION_UNACCEPTABLE);
    }
}

void NasMm::receiveAuthenticationResult(const nas::AuthenticationResult &msg)
{
    if (msg.abba.has_value())
        m_usim->m_nonCurrentNsCtx->keys.abba = msg.abba->rawData.copy();

    if (msg.eapMessage.eap->code == eap::ECode::SUCCESS)
        receiveEapSuccessMessage(*msg.eapMessage.eap);
    else if (msg.eapMessage.eap->code == eap::ECode::FAILURE)
        receiveEapFailureMessage(*msg.eapMessage.eap);
    else
        m_logger->warn("Network sent EAP with an inconvenient type in Authentication Result, ignoring EAP IE.");
}

void NasMm::receiveAuthenticationReject(const nas::AuthenticationReject &msg)
{
    m_logger->err("Authentication Reject received");

    // The RAND and RES* values stored in the ME shall be deleted and timer T3516, if running, shall be stopped
    m_usim->m_rand = {};
    m_usim->m_resStar = {};
    m_timers->t3516.stop();

    if (msg.eapMessage.has_value() && msg.eapMessage->eap)
    {
        if (msg.eapMessage->eap->code == eap::ECode::FAILURE)
            receiveEapFailureMessage(*msg.eapMessage->eap);
        else
            m_logger->warn("Network sent EAP with inconvenient type in AuthenticationReject, ignoring EAP IE.");
    }

    // The UE shall set the update status to 5U3 ROAMING NOT ALLOWED,
    switchUState(E5UState::U3_ROAMING_NOT_ALLOWED);
    // Delete the stored 5G-GUTI, TAI list, last visited registered TAI and ngKSI. The USIM shall be considered invalid
    // until switching off the UE or the UICC containing the USIM is removed
    m_storage->storedGuti->clear();
    m_storage->lastVisitedRegisteredTai->clear();
    m_storage->taiList->clear();
    m_usim->m_currentNsCtx = {};
    m_usim->m_nonCurrentNsCtx = {};
    m_usim->invalidate();
    // The UE shall abort any 5GMM signalling procedure, stop any of the timers T3510, T3516, T3517, T3519 or T3521 (if
    // they were running) ..
    m_timers->t3510.stop();
    m_timers->t3516.stop();
    m_timers->t3517.stop();
    m_timers->t3519.stop();
    m_timers->t3521.stop();
    // .. and enter state 5GMM-DEREGISTERED.
    switchMmState(EMmSubState::MM_DEREGISTERED_PS);
}

void NasMm::receiveEapSuccessMessage(const eap::Eap &eap)
{
    // do nothing
}

void NasMm::receiveEapFailureMessage(const eap::Eap &eap)
{
    m_logger->debug("Handling EAP-failure");

    // UE shall delete the partial native 5G NAS security context if any was created
    m_usim->m_nonCurrentNsCtx = {};
}

EAutnValidationRes NasMm::validateAutn(const OctetString &rand, const OctetString &autn)
{
    // Decode AUTN
    OctetString receivedSQNxorAK = autn.subCopy(0, 6);
    OctetString receivedAMF = autn.subCopy(6, 2);
    OctetString receivedMAC = autn.subCopy(8, 8);

    // Check the separation bit
    if (receivedAMF.get(0).bit(7) != 1)
    {
        m_logger->err("AUTN validation SEP-BIT failure. expected: 1, received: 0");
        return EAutnValidationRes::AMF_SEPARATION_BIT_FAILURE;
    }

    // Derive AK and MAC
    auto milenage = calculateMilenage(m_usim->m_sqnMng->getSqn(), rand, false);
    OctetString receivedSQN = OctetString::Xor(receivedSQNxorAK, milenage.ak);

    m_logger->debug("Received SQN [%s]", receivedSQN.toHexString().c_str());
    m_logger->debug("SQN-MS [%s]", m_usim->m_sqnMng->getSqn().toHexString().c_str());

    // Verify that the received sequence number SQN is in the correct range
    bool sqn_ok = m_usim->m_sqnMng->checkSqn(receivedSQN);

    // Re-execute the milenage calculation (if case of sqn is changed with the received value)
    milenage = calculateMilenage(receivedSQN, rand, false);

    // Check MAC
    if (receivedMAC != milenage.mac_a)
    {
        m_logger->err("AUTN validation MAC mismatch. expected [%s] received [%s]", milenage.mac_a.toHexString().c_str(),
                      receivedMAC.toHexString().c_str());
        return EAutnValidationRes::MAC_FAILURE;
    }

    if(!sqn_ok)
        return EAutnValidationRes::SYNCHRONISATION_FAILURE;

    return EAutnValidationRes::OK;
}

crypto::milenage::Milenage NasMm::calculateMilenage(const OctetString &sqn, const OctetString &rand, bool dummyAmf)
{
    OctetString amf = dummyAmf ? OctetString::FromSpare(2) : m_base->config->amf.copy();

    if (m_base->config->opType == OpType::OPC)
        return crypto::milenage::Calculate(m_base->config->opC, m_base->config->key, rand, sqn, amf);

    OctetString opc = crypto::milenage::CalculateOpC(m_base->config->opC, m_base->config->key);
    return crypto::milenage::Calculate(opc, m_base->config->key, rand, sqn, amf);
}

bool NasMm::networkFailingTheAuthCheck(bool hasChance)
{
    if (hasChance && m_nwConsecutiveAuthFailure++ < 3)
        return false;

    // NOTE: Normally if we should check if the UE has an emergency. If it has, it should consider as network passed the
    //  auth check, instead of performing the actions in the following lines. But it's difficult to maintain and
    //  implement this behaviour. Therefore we would expect other solutions for an emergency case. Such as
    //  - Network initiates a Security Mode Command with IA0 and EA0
    //  - UE performs emergency registration after releasing the connection
    // END

    m_logger->err("Network failing the authentication check");

    if (m_cmState == ECmState::CM_CONNECTED)
        localReleaseConnection(true);

    m_timers->t3520.stop();
    return true;
}

} // namespace nr::ue
