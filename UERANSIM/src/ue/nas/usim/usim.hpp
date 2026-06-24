//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "sqn_mng.hpp"

#include <memory>
#include <optional>

#include <lib/nas/msg.hpp>
#include <ue/types.hpp>
#include <utils/common_types.hpp>
#include <utils/octet_string.hpp>

namespace nr::ue
{

class Usim
{
  private:
    bool m_isValid{};

  public:
    // Security related
    std::unique_ptr<NasSecurityContext> m_currentNsCtx{};
    std::unique_ptr<NasSecurityContext> m_nonCurrentNsCtx{};
    OctetString m_rand{};
    OctetString m_resStar{};
    std::unique_ptr<SqnManager> m_sqnMng{};

    // Others
    bool m_isECallOnly = false;   // todo: configurable
    bool m_emgIndication = false; // todo: configurable

    //tahap-9 //Prime-FS
    OctetString m_eccPrivKey; // Diset saat generate UE pub/priv key (saat sebelum kirim AT_PUB_ECDHE)
    OctetString m_eccPubKey; // Diset saat generate UE pub/priv key (saat sebelum kirim AT_PUB_ECDHE)
    //end

    //tahap-10 //HPQC
    OctetString m_mlkemCiphertext; // untuk simpan ct_M hasil encapsulate
    //end

  public:
    void initialize(bool hasSupi);

    bool isValid();
    void invalidate();
};

} // namespace nr::ue