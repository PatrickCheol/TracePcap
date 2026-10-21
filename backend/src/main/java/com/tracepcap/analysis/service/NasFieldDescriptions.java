package com.tracepcap.analysis.service;

import java.util.Map;

/** Short explanations supplementing the decoder's exact field values and bit masks. */
public final class NasFieldDescriptions {

  private NasFieldDescriptions() {}

  private static final Map<String, String> HELP =
      Map.ofEntries(
          Map.entry("epd", "NAS 메시지의 종류를 구분합니다. 5GMM은 등록·이동성 관리, 5GSM은 PDU 세션 관리를 담당합니다."),
          Map.entry(
              "security_header_type",
              "NAS 보안 헤더의 보호 방식을 나타냅니다. 0은 평문, 1·3은 무결성 보호, 2·4는 무결성 보호와 암호화입니다. 보호 유형만으로 MAC 검증이나 복호화가 완료된 것은 아닙니다."),
          Map.entry(
              "msg_auth_code",
              "NAS 무결성 보호에 쓰이는 메시지 인증 코드(MAC)입니다. 이 값을 읽는 것과 올바른 키·보안 문맥으로 검증하는 것은 별개입니다."),
          Map.entry(
              "seq_no",
              "보호된 NAS 메시지의 시퀀스 번호입니다. 전체 NAS COUNT의 일부이므로 이 바이트만으로 전체 카운터나 재전송 공격을 판정할 수 없습니다."),
          Map.entry(
              "mm.message_type", "등록·인증·보안 설정 등 5GMM 절차의 메시지 종류입니다. 구체적인 이름은 디코더의 해석값에 표시됩니다."),
          Map.entry("sm.message_type", "PDU 세션 생성·변경·해제 등 5GSM 절차의 메시지 종류입니다."),
          Map.entry(
              "mm.5gs_reg_type",
              "최초 등록, 이동성 갱신, 주기적 갱신 등 단말이 요청하는 등록 유형입니다. 같은 바이트의 다른 비트와 구분해서 읽습니다."),
          Map.entry("mm.for", "등록 후 추가 시그널링이나 서비스 요청을 이어갈 의사를 나타내는 Follow-On Request 비트입니다."),
          Map.entry(
              "mm.tsc", "NAS 키 세트 식별자와 함께 사용되는 보안 문맥 유형 비트입니다. Native 또는 mapped 보안 문맥을 구분합니다."),
          Map.entry("mm.tsc.h1", "상위 반바이트에 실린 보안 문맥 유형 비트입니다. 표시된 마스크에 해당하는 비트만 선택됩니다."),
          Map.entry("mm.type_id", "5G-GUTI·SUCI 등 이동 가입자 식별자의 형식을 구분합니다."),
          Map.entry(
              "mm.nas_sec_algo_enc", "네트워크가 선택한 NAS 암호화 알고리즘입니다. 지원 능력 비트와 실제 선택된 알고리즘은 구분해야 합니다."),
          Map.entry(
              "mm.nas_sec_algo_ip",
              "네트워크가 선택한 NAS 무결성 보호 알고리즘입니다. 이 필드가 존재하는 것만으로 메시지 무결성이 검증되지는 않습니다."),
          Map.entry("mm.5gmm_cause", "5GMM 절차의 거절·실패 등을 설명하는 원인값입니다. 앞뒤 메시지와 함께 해석해야 합니다."),
          Map.entry("sm.5gsm_cause", "PDU 세션 관리 절차의 거절·실패 등을 설명하는 원인값입니다."),
          Map.entry("pdu_session_id", "NAS 세션 관리 메시지가 대상으로 하는 PDU 세션 식별자입니다."),
          Map.entry("proc_trans_id", "5GSM 요청과 응답을 연결하는 절차 트랜잭션 식별자입니다."),
          Map.entry("sm.pdu_session_type", "IPv4·IPv6·IPv4v6 등 PDU 세션의 데이터 유형입니다."),
          Map.entry("sm.pdu_ses_type", "IPv4·IPv6·IPv4v6 등 PDU 세션의 데이터 유형입니다."),
          Map.entry("cmn.dnn", "단말이 접속하려는 데이터 네트워크의 이름(DNN)입니다."),
          Map.entry("mm.sst", "S-NSSAI의 Slice/Service Type입니다. SD와 함께 네트워크 슬라이스를 식별하는 데 사용됩니다."),
          Map.entry("mm.mm_sd", "S-NSSAI의 Slice Differentiator입니다. 같은 SST의 슬라이스를 추가로 구분합니다."),
          Map.entry("mm.suci.supi_fmt", "SUCI 내부에서 사용하는 SUPI 형식입니다."),
          Map.entry("mm.suci.routing_indicator", "홈 네트워크가 SUCI를 처리할 경로를 선택하는 데 사용하는 식별자입니다."),
          Map.entry(
              "mm.suci.scheme_id",
              "SUCI 가입자 식별정보 보호 방식의 식별자입니다. 값 0은 null scheme이며 적용 정책과 함께 점검해야 합니다."),
          Map.entry("mm.suci.pki", "SUCI 생성에 사용한 홈 네트워크 공개키의 식별자입니다. 공개키 자체가 아닙니다."),
          Map.entry(
              "mm.suci.scheme_output", "SUCI 보호 방식이 생성한 출력 데이터입니다. 원본 가입자 식별자의 평문 복원과는 별개입니다."),
          Map.entry(
              "mm.suci.scheme_output.ciphertext",
              "SUCI 보호 방식의 암호문입니다. 이 분석기는 키 없이 평문을 복원하지 않습니다."));

  public static String describe(String fieldName) {
    if (fieldName == null) return null;
    String normalized = fieldName.replace("nas_5gs", "nas-5gs");
    if (normalized.equals("nas-5gs")) {
      return "단말(UE)과 코어 사이의 5GS NAS 메시지입니다. 등록·인증·보안 설정·PDU 세션 관리에 사용되며, NGAP 등에 포함되어 전달될 수 있습니다.";
    }
    if (!normalized.startsWith("nas-5gs.")) return null;
    String field = normalized.substring("nas-5gs.".length());
    String help = HELP.get(field);
    if (help != null) return help;
    if (field.matches("mm\\.((128_5g_|5g_128_|5g_)ea[0-7]|ea0)")) {
      return "UE 보안 능력에서 해당 5G 암호화 알고리즘의 지원 여부를 나타내는 비트입니다. 실제로 선택되거나 사용된 알고리즘을 뜻하지는 않습니다.";
    }
    if (field.matches("mm\\.((128_5g_|5g_128_|5g_)ia[0-7]|ia0)")) {
      return "UE 보안 능력에서 해당 5G 무결성 보호 알고리즘의 지원 여부를 나타내는 비트입니다. 실제 MAC 검증 결과를 뜻하지는 않습니다.";
    }
    if (field.startsWith("spare")) {
      return "현재 메시지 형식에서 여분으로 정의된 비트입니다. 비트 위치와 원본 값은 디코더의 마스크로 확인할 수 있습니다.";
    }
    return null;
  }
}
