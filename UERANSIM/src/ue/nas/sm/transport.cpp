//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "sm.hpp"

#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <stdexcept>

#include <lib/nas/utils.hpp>
#include <ue/nas/mm/mm.hpp>

namespace nr::ue
{

static constexpr size_t EDHOC_FRAG_FIRST_CAP = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN - E4_EDHOC_FRAG_LEN_LEN;
static constexpr size_t EDHOC_FRAG_NEXT_CAP = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN;

static OctetString EncodeEdhocFragment(const uint8_t *payload, size_t payloadLen, size_t &payloadPos)
{
    uint8_t wire[E4_MAX_MSG + E4_EDHOC_FRAG_HDR_LEN + E4_EDHOC_FRAG_LEN_LEN]{};

    if (payloadPos > payloadLen)
        return OctetString();

    size_t remaining = payloadLen - payloadPos;
    size_t fragCap = (payloadPos == 0) ? EDHOC_FRAG_FIRST_CAP : EDHOC_FRAG_NEXT_CAP;
    size_t fragLen = remaining < fragCap ? remaining : fragCap;
    size_t wireLen = E4_EDHOC_FRAG_HDR_LEN + ((payloadPos == 0 && remaining > fragLen) ? E4_EDHOC_FRAG_LEN_LEN : 0) + fragLen;

    wire[0] = ((remaining > fragLen) ? E4_EDHOC_FRAG_FLAG_MORE : 0) |
              ((payloadPos == 0 && remaining > fragLen) ? E4_EDHOC_FRAG_FLAG_LEN : 0);

    size_t pos = 1;
    if (payloadPos == 0 && remaining > fragLen)
    {
        uint16_t total = htons(static_cast<uint16_t>(payloadLen));
        std::memcpy(wire + pos, &total, sizeof(total));
        pos += sizeof(total);
    }

    std::memcpy(wire + pos, payload + payloadPos, fragLen);
    payloadPos += fragLen;
    return OctetString::FromArray(wire, wireLen);
}

static bool ParseEdhocWire(const OctetString &wire, uint8_t *inBuf, size_t &inLen,
                           size_t &inPos, const uint8_t *&msg, size_t &msgLen,
                           bool &needAck)
{
    const uint8_t *data = wire.data();
    size_t dataLen = static_cast<size_t>(wire.length());

    needAck = false;
    msg = nullptr;
    msgLen = 0;

    if (!data || dataLen == 0)
        return false;

    uint8_t flags = data[0];
    size_t pos = 1;

    if (flags & E4_EDHOC_FRAG_FLAG_LEN)
    {
        if (dataLen < 3)
            return false;

        uint16_t total = 0;
        std::memcpy(&total, data + 1, sizeof(total));
        total = ntohs(total);
        pos = 3;
        if (total == 0 || total > E4_MAX_MSG)
            return false;

        if (inLen == 0)
        {
            inLen = total;
            inPos = 0;
        }
        else if (inLen != total)
        {
            return false;
        }
    }

    if (dataLen < pos)
        return false;

    size_t payloadLen = dataLen - pos;
    if (inLen > 0)
    {
        if ((inPos + payloadLen) > inLen)
            return false;

        std::memcpy(inBuf + inPos, data + pos, payloadLen);
        inPos += payloadLen;

        if (flags & E4_EDHOC_FRAG_FLAG_MORE)
        {
            needAck = true;
            return true;
        }

        if (inPos != inLen)
            return false;

        msg = inBuf;
        msgLen = inLen;
        inLen = 0;
        inPos = 0;
        return true;
    }

    if (flags & E4_EDHOC_FRAG_FLAG_MORE)
        return false;

    msg = data + pos;
    msgLen = payloadLen;
    return true;
}

static ENasTransportHint MapMsgTypeToHint(nas::EMessageType msgType)
{
    switch (msgType)
    {
    case nas::EMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
        return ENasTransportHint::PDU_SESSION_ESTABLISHMENT_REQUEST;
    case nas::EMessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT:
        return ENasTransportHint::PDU_SESSION_ESTABLISHMENT_ACCEPT;
    case nas::EMessageType::PDU_SESSION_ESTABLISHMENT_REJECT:
        return ENasTransportHint::PDU_SESSION_ESTABLISHMENT_REJECT;
    case nas::EMessageType::PDU_SESSION_AUTHENTICATION_COMMAND:
        return ENasTransportHint::PDU_SESSION_AUTHENTICATION_COMMAND;
    case nas::EMessageType::PDU_SESSION_AUTHENTICATION_COMPLETE:
        return ENasTransportHint::PDU_SESSION_AUTHENTICATION_COMPLETE;
    case nas::EMessageType::PDU_SESSION_AUTHENTICATION_RESULT:
        return ENasTransportHint::PDU_SESSION_AUTHENTICATION_RESULT;
    case nas::EMessageType::PDU_SESSION_MODIFICATION_REQUEST:
        return ENasTransportHint::PDU_SESSION_MODIFICATION_REQUEST;
    case nas::EMessageType::PDU_SESSION_MODIFICATION_REJECT:
        return ENasTransportHint::PDU_SESSION_MODIFICATION_REJECT;
    case nas::EMessageType::PDU_SESSION_MODIFICATION_COMMAND:
        return ENasTransportHint::PDU_SESSION_MODIFICATION_COMMAND;
    case nas::EMessageType::PDU_SESSION_MODIFICATION_COMPLETE:
        return ENasTransportHint::PDU_SESSION_MODIFICATION_COMPLETE;
    case nas::EMessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT:
        return ENasTransportHint::PDU_SESSION_MODIFICATION_COMMAND_REJECT;
    case nas::EMessageType::PDU_SESSION_RELEASE_REQUEST:
        return ENasTransportHint::PDU_SESSION_RELEASE_REQUEST;
    case nas::EMessageType::PDU_SESSION_RELEASE_REJECT:
        return ENasTransportHint::PDU_SESSION_RELEASE_REJECT;
    case nas::EMessageType::PDU_SESSION_RELEASE_COMMAND:
        return ENasTransportHint::PDU_SESSION_RELEASE_COMMAND;
    case nas::EMessageType::PDU_SESSION_RELEASE_COMPLETE:
        return ENasTransportHint::PDU_SESSION_RELEASE_COMPLETE;
    case nas::EMessageType::FIVEG_SM_STATUS:
        return ENasTransportHint::FIVEG_SM_STATUS;
    default:
        throw std::runtime_error("failure in MapMsgTypeToHint");
    }
}

void NasSm::sendSmMessage(int psi, const nas::SmMessage &msg)
{
    auto &session = m_pduSessions[psi];

    nas::UlNasTransport m;
    m.payloadContainerType.payloadContainerType = nas::EPayloadContainerType::N1_SM_INFORMATION;
    nas::EncodeNasMessage(msg, m.payloadContainer.data);
    m.pduSessionId = nas::IEPduSessionIdentity2{};
    m.pduSessionId->value = psi;

    if (msg.messageType == nas::EMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST ||
        msg.messageType == nas::EMessageType::PDU_SESSION_MODIFICATION_REQUEST)
    {
        m.requestType = nas::IERequestType{};
        m.requestType->requestType =
            session->isEmergency ? nas::ERequestType::INITIAL_EMERGENCY_REQUEST : nas::ERequestType::INITIAL_REQUEST;

        if (!session->isEmergency)
        {
            if (session->sNssai.has_value())
                m.sNssai = nas::utils::SNssaiFrom(*session->sNssai);

            if (session->apn.has_value())
                m.dnn = nas::utils::DnnFromApn(*session->apn);
        }
    }

    m_mm->deliverUlTransport(m, MapMsgTypeToHint(msg.messageType));
}

void NasSm::receiveSmMessage(const nas::SmMessage &msg)
{
    switch (msg.messageType)
    {
    case nas::EMessageType::PDU_SESSION_AUTHENTICATION_COMMAND:
        receivePduSessionAuthenticationCommand((const nas::PduSessionAuthenticationCommand &)msg);
        break;
    case nas::EMessageType::PDU_SESSION_AUTHENTICATION_RESULT:
        receivePduSessionAuthenticationResult((const nas::PduSessionAuthenticationResult &)msg);
        break;
    case nas::EMessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT:
        receiveEstablishmentAccept((const nas::PduSessionEstablishmentAccept &)msg);
        break;
    case nas::EMessageType::PDU_SESSION_ESTABLISHMENT_REJECT:
        receiveEstablishmentReject((const nas::PduSessionEstablishmentReject &)msg);
        break;
    case nas::EMessageType::PDU_SESSION_RELEASE_REJECT:
        receiveReleaseReject((const nas::PduSessionReleaseReject &)msg);
        break;
    case nas::EMessageType::PDU_SESSION_RELEASE_COMMAND:
        receiveReleaseCommand((const nas::PduSessionReleaseCommand &)msg);
        break;
    case nas::EMessageType::FIVEG_SM_STATUS:
        receiveSmStatus((const nas::FiveGSmStatus &)msg);
        break;
    default:
        m_logger->err("Unhandled NAS SM message received: %d", (int)msg.messageType);
        break;
    }
}

void NasSm::receivePduSessionAuthenticationCommand(const nas::PduSessionAuthenticationCommand &msg)
{
    nas::PduSessionAuthenticationComplete resp;

    m_logger->info("PDU Session Authentication Command received for PSI[%d]", msg.pduSessionId);

    resp.pduSessionId = msg.pduSessionId;
    resp.pti = msg.pti;

    if (!msg.eapMessage.eap)
    {
        m_logger->err("Missing EAP payload in PDU Session Authentication Command");
        sendSmCause(nas::ESmCause::INVALID_MANDATORY_INFORMATION, msg.pti, msg.pduSessionId);
        return;
    }

    if (msg.eapMessage.eap->eapType == eap::EEapType::EAP_EDHOC)
    {
        const auto &in = (const eap::EapEdhoc &)*msg.eapMessage.eap;
        OctetString outData;

        if (!ensureEdhocProvisioned())
        {
            m_logger->err("EAP-EDHOC: missing provisioning material, cannot run secondary authentication");
            sendSmCause(nas::ESmCause::INSUFFICIENT_RESOURCES, msg.pti, msg.pduSessionId);
            return;
        }

        const uint8_t *inData = in.rawData.data();
        size_t inLen = static_cast<size_t>(in.rawData.length());
        uint8_t buf[E4_MAX_MSG];
        size_t outLen = 0;
        int rc = E4_OK;

        if (m_edhocOutPos < m_edhocOutLen)
        {
            outData = EncodeEdhocFragment(m_edhocOut, m_edhocOutLen, m_edhocOutPos);
            if (outData.length() == 0)
            {
                m_logger->err("EAP-EDHOC: failed to continue fragmented response");
                sendSmCause(nas::ESmCause::INSUFFICIENT_RESOURCES, msg.pti, msg.pduSessionId);
                return;
            }

            if (m_edhocOutPos >= m_edhocOutLen)
                m_logger->info("EAP-EDHOC: completed fragmented response");
            else
                m_logger->info("EAP-EDHOC: continued fragmented response (%zu bytes remaining)",
                               m_edhocOutLen - m_edhocOutPos);
        }
        else if (m_edhocRound < 0)
        {
            if (!(inLen == 1 && inData[0] == 0x01))
            {
                m_logger->err("EAP-EDHOC: invalid start indication");
                sendSmCause(nas::ESmCause::INVALID_MANDATORY_INFORMATION, msg.pti, msg.pduSessionId);
                return;
            }

            edhoc4_init_initiator(&m_edhocCtx, &m_edhocCreds, m_edhocPeerPub);
            rc = edhoc4_i_make_msg1(&m_edhocCtx, buf, sizeof(buf), &outLen);
            if (rc == E4_OK)
            {
                m_edhocRound = 1;
                std::memcpy(m_edhocOut, buf, outLen);
                m_edhocOutLen = outLen;
                m_edhocOutPos = 0;
                outData = EncodeEdhocFragment(m_edhocOut, m_edhocOutLen, m_edhocOutPos);
                if (outData.length() == 0)
                    rc = E4_ERR_BUF;
                else if (m_edhocOutPos >= m_edhocOutLen)
                    m_logger->info("EAP-EDHOC: sent message_1 (%zu bytes)", outLen);
                else
                    m_logger->info("EAP-EDHOC: sent message_1 fragment (%zu/%zu bytes)",
                                   m_edhocOutPos, m_edhocOutLen);
            }
        }
        else
        {
            bool needAck = false;
            const uint8_t *msgData = nullptr;
            size_t msgLen = 0;

            if (!ParseEdhocWire(in.rawData, m_edhocIn, m_edhocInLen, m_edhocInPos, msgData, msgLen, needAck))
            {
                m_logger->err("EAP-EDHOC: fragment parse error while waiting for round %d", m_edhocRound);
                sendSmCause(nas::ESmCause::INVALID_MANDATORY_INFORMATION, msg.pti, msg.pduSessionId);
                return;
            }

            if (needAck)
            {
                uint8_t ackWire[1] = {0x00};
                outData = OctetString::FromArray(ackWire, sizeof(ackWire));
                resp.eapMessage.eap = std::make_unique<eap::EapEdhoc>(
                    eap::ECode::RESPONSE, msg.eapMessage.eap->id, std::move(outData));
                sendSmMessage(msg.pduSessionId, resp);
                return;
            }

            if (m_edhocRound == 1)
            {
                rc = edhoc4_i_handle_msg2(&m_edhocCtx, msgData, msgLen, buf, sizeof(buf), &outLen);
                if (rc == E4_OK)
                {
                    m_edhocRound = 2;
                    std::memcpy(m_edhocOut, buf, outLen);
                    m_edhocOutLen = outLen;
                    m_edhocOutPos = 0;
                    outData = EncodeEdhocFragment(m_edhocOut, m_edhocOutLen, m_edhocOutPos);
                    if (outData.length() == 0)
                        rc = E4_ERR_BUF;
                    else if (m_edhocOutPos >= m_edhocOutLen)
                        m_logger->info("EAP-EDHOC: sent message_3 (%zu bytes)", outLen);
                    else
                        m_logger->info("EAP-EDHOC: sent message_3 fragment (%zu/%zu bytes)",
                                       m_edhocOutPos, m_edhocOutLen);
                }
            }
            else if (m_edhocRound == 2)
            {
                rc = edhoc4_i_handle_msg4(&m_edhocCtx, msgData, msgLen);
                if (rc == E4_OK)
                {
                    uint8_t ackWire[1] = {0x00};
                    outData = OctetString::FromArray(ackWire, sizeof(ackWire));
                    m_edhocRound = 3;
                    m_logger->info("EAP-EDHOC: handshake complete, MSK/EMSK derived");
                }
            }
            else
            {
                uint8_t ackWire[1] = {0x00};
                outData = OctetString::FromArray(ackWire, sizeof(ackWire));
            }
        }

        if (rc != E4_OK)
        {
            m_logger->err("EAP-EDHOC: protocol error at round %d: %s", m_edhocRound,
                          edhoc4_strerror(rc));
            m_edhocRound = -1; // reset for a possible retry
            m_edhocInLen = 0;
            m_edhocInPos = 0;
            m_edhocOutLen = 0;
            m_edhocOutPos = 0;
            sendSmCause(nas::ESmCause::INSUFFICIENT_RESOURCES, msg.pti, msg.pduSessionId);
            return;
        }

        resp.eapMessage.eap = std::make_unique<eap::EapEdhoc>(
            eap::ECode::RESPONSE, msg.eapMessage.eap->id, std::move(outData));
    }
    else if (msg.eapMessage.eap->eapType == eap::EEapType::IDENTITY)
    {
        std::string identity = "imsi-000000000000000";
        if (m_base && m_base->config && m_base->config->supi.has_value())
            identity = m_base->config->supi.value().value;

        resp.eapMessage.eap = std::make_unique<eap::EapIdentity>(
            eap::ECode::RESPONSE,
            msg.eapMessage.eap->id,
            OctetString::FromAscii(identity));
    }
    else
    {
        m_logger->warn("Unsupported EAP type [%d] in secondary authentication, returning Notification",
                       (int)msg.eapMessage.eap->eapType);

        resp.eapMessage.eap = std::make_unique<eap::EapNotification>(
            eap::ECode::RESPONSE,
            msg.eapMessage.eap->id,
            OctetString::FromAscii("UNSUPPORTED-EAP"));
    }

    sendSmMessage(msg.pduSessionId, resp);
}

bool NasSm::ensureEdhocProvisioned()
{
    if (m_edhocProvisioned)
        return true;

    const char *credsPath = std::getenv("EDHOC_UE_CREDS");
    const char *pubPath = std::getenv("EDHOC_SRV_PUB");
    if (!credsPath)
        credsPath = "/usr/local/etc/edhoc/ue.creds";
    if (!pubPath)
        pubPath = "/usr/local/etc/edhoc/server.pub";

    if (edhoc4_creds_load(credsPath, &m_edhocCreds) != E4_OK)
    {
        m_logger->err("EAP-EDHOC: failed to load UE credentials from %s", credsPath);
        return false;
    }
    if (edhoc4_pub_load(pubPath, m_edhocPeerPub) != E4_OK)
    {
        m_logger->err("EAP-EDHOC: failed to load DN-AAA public key from %s", pubPath);
        return false;
    }

    m_edhocProvisioned = true;
    m_logger->info("EAP-EDHOC: loaded method-4 SIGMA XWING credentials");
    return true;
}

void NasSm::receivePduSessionAuthenticationResult(const nas::PduSessionAuthenticationResult &msg)
{
    if (msg.eapMessage.has_value() && msg.eapMessage->eap)
    {
        m_logger->info("PDU Session Authentication Result with EAP type [%d] for PSI[%d]",
                       (int)msg.eapMessage->eap->eapType, msg.pduSessionId);
    }
    else
    {
        m_logger->info("PDU Session Authentication Result received for PSI[%d]", msg.pduSessionId);
    }
}

void NasSm::receiveSmStatus(const nas::FiveGSmStatus &msg)
{
    m_logger->err("SM Status received with cause [%s]", nas::utils::EnumToString(msg.smCause.value));

    if (msg.smCause.value == nas::ESmCause::INVALID_PTI_VALUE)
    {
        // "The UE shall abort any ongoing 5GSM procedure related to the received PTI value and stop any related timer."
        abortProcedureByPti(msg.pti);
    }
    else if (msg.smCause.value == nas::ESmCause::MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED)
    {
        // "The UE shall abort any ongoing 5GSM procedure related to the PTI or PDU session Id and stop any related
        // timer."
        abortProcedureByPtiOrPsi(msg.pti, msg.pduSessionId);
    }
}

void NasSm::sendSmCause(const nas::ESmCause &cause, int pti, int psi)
{
    m_logger->warn("Sending SM Cause[%s] for PSI[%d]", nas::utils::EnumToString(cause), psi);

    nas::FiveGSmStatus smStatus;
    smStatus.smCause.value = cause;
    smStatus.pti = pti;
    smStatus.pduSessionId = psi;

    nas::UlNasTransport ulTransport;
    ulTransport.payloadContainerType.payloadContainerType = nas::EPayloadContainerType::N1_SM_INFORMATION;
    nas::EncodeNasMessage(smStatus, ulTransport.payloadContainer.data);
    ulTransport.pduSessionId = nas::IEPduSessionIdentity2{};
    ulTransport.pduSessionId->value = psi;

    m_mm->deliverUlTransport(ulTransport, ENasTransportHint::FIVEG_SM_STATUS);
}

void NasSm::receiveForwardingFailure(const nas::SmMessage &msg, nas::EMmCause cause,
                                     const std::optional<nas::IEGprsTimer3> &backoffTimer)
{
    // TODO: other actions such as congestion control etc

    m_logger->err("SM forwarding failure for message type[%d] with cause[%s]", static_cast<int>(msg.messageType),
                  nas::utils::EnumToString(cause));

    if (!checkPtiAndPsi(msg))
        return;

    abortProcedureByPti(msg.pti);
}

} // namespace nr::ue
