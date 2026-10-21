package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;

class PacketEvidenceExtractorTest {
  final UUID fileId = UUID.randomUUID();
  final UUID conversationId = UUID.randomUUID();
  final ObjectMapper mapper = new ObjectMapper();

  @Test
  void realSuciRetainsIdentityParentPlmnLabelsRawOffsetsAndMasks() throws Exception {
    var evidence =
        PacketEvidenceFixture.identity(fileId, conversationId).evidenceFor(fileId, "SUCI가 뭔지 분석해줘");
    JsonNode json = mapper.readTree(evidence.json());
    var fields = json.get("fields");
    Map<String, JsonNode> byName = new HashMap<>();
    fields.forEach(f -> byName.put(f.path("name").asText(), f));
    for (String name :
        List.of(
            "nas_5gs.mm.type_id",
            "nas_5gs.mm.suci.supi_fmt",
            "e212.mcc",
            "e212.mnc",
            "nas_5gs.mm.suci.routing_indicator",
            "nas_5gs.mm.suci.scheme_id",
            "nas_5gs.mm.suci.pki",
            "nas_5gs.mm.suci.msin")) {
      assertThat(byName).containsKey(name);
      assertThat(byName.get(name).get("path").asText()).contains("5GS mobile identity");
      assertThat(byName.get(name).get("conversationId").asText())
          .isEqualTo(conversationId.toString());
      assertThat(byName.get(name).get("packetNumber").asInt()).isEqualTo(1);
    }
    assertThat(byName.get("e212.mnc").get("label").asText()).contains("(01)");
    assertThat(byName.get("e212.mcc").get("rawValue").asText()).isEqualTo("00f1");
    assertThat(byName.get("nas_5gs.mm.suci.scheme_id").get("value").asText()).isEqualTo("0");
    assertThat(byName.get("nas_5gs.mm.suci.scheme_id").get("byteOffset").asInt()).isEqualTo(92);
    assertThat(byName.get("nas_5gs.mm.suci.scheme_id").get("bitmask").asText()).isEqualTo("0xf");
    assertThat(byName.get("nas_5gs.mm.suci.msin").get("value").asText()).isEqualTo("00000010");
    assertThat(evidence.json().length())
        .isLessThanOrEqualTo(PacketEvidenceExtractor.MAX_PROMPT_CHARS);
  }

  @Test
  void genericHttpEvidenceUsesSameVerifiedReassemblySourceAsInspector() throws Exception {
    var evidence =
        PacketEvidenceFixture.http(fileId, conversationId).evidenceFor(fileId, "HTTP 요청메서드?");
    JsonNode fields = mapper.readTree(evidence.json()).get("fields");
    JsonNode method = null;
    for (var field : fields)
      if (field.path("name").asText().equals("http.request.method")) method = field;
    assertThat(method).isNotNull();
    assertThat(method.get("value").asText()).isEqualTo("GET");
    assertThat(method.get("source").asText()).isEqualTo("reassembled");
    assertThat(method.get("byteOffset").isNull()).isTrue();
  }

  @Test
  void selectionNeverInterpolatesQuestionAsDecoderCodeAndPrioritizesIdentity() {
    var selection = PacketEvidenceExtractor.selection("SUCI || frame; $(echo malicious)");
    assertThat(selection.filter()).isEqualTo("nas-5gs");
    var candidates =
        PacketEvidenceExtractor.candidates(
            "1\teth:ip:sctp:nas-5gs\t\n90\teth:ip:sctp:nas-5gs\t1\n"
                .getBytes(StandardCharsets.UTF_8));
    assertThat(PacketEvidenceExtractor.select(candidates, true).get(0).number()).isEqualTo(90);
    assertThat(PacketEvidenceExtractor.selection("패킷 25 내용").filter())
        .isEqualTo("frame.number == 25");
  }

  @Test
  void omissionBudgetIsExplicitAndJsonAlwaysFitsPromptBound() throws Exception {
    StringBuilder pdml =
        new StringBuilder("<pdml><packet><proto name='http'><field name='frame.number' show='1'/>");
    for (int i = 0; i < 1200; i++)
      pdml.append("<field name='http.test")
          .append(i)
          .append("' show='")
          .append("x".repeat(500))
          .append("' size='0'/>");
    pdml.append("</proto></packet></pdml>");
    var extractor =
        PacketEvidenceFixture.extractor(
            fileId,
            conversationId,
            1,
            "http",
            "",
            pdml.toString().getBytes(StandardCharsets.UTF_8),
            "[{\"_source\":{\"layers\":{\"frame_raw\":[\"0001\",0,2,0,1]}}}]"
                .getBytes(StandardCharsets.UTF_8));
    var evidence = extractor.evidenceFor(fileId, "HTTP");
    assertThat(evidence.coverage().status()).isEqualTo("partial");
    assertThat(evidence.coverage().includedFields()).isLessThanOrEqualTo(400);
    assertThat(evidence.coverage().omittedFields()).isGreaterThan(0);
    assertThat(evidence.json().length()).isLessThanOrEqualTo(64_000);
    assertThat(evidence.coverage().warnings()).anyMatch(w -> w.contains("omitted"));
  }

  @Test
  void inaccessibleCaptureReturnsHonestUnavailableCoverageWithoutCallingModel() {
    FileRepository files = mock(FileRepository.class);
    when(files.findById(fileId))
        .thenReturn(
            Optional.of(
                FileEntity.builder()
                    .id(fileId)
                    .minioPath("missing")
                    .fileSize(2L)
                    .packetCount(2)
                    .build()));
    StorageService storage = mock(StorageService.class);
    when(storage.downloadFile("missing")).thenThrow(new RuntimeException("not available"));
    var runner = mock(TsharkDissectionRunner.class);
    var extractor =
        new PacketEvidenceExtractor(
            files,
            mock(PacketLookup.class),
            storage,
            runner,
            mock(TsharkFieldRegistry.class),
            new PacketDissectionParser(),
            mapper);
    var evidence = extractor.evidenceFor(fileId, "SUCI");
    assertThat(evidence.coverage().status()).isEqualTo("unavailable");
    assertThat(evidence.coverage().decodedFrames()).isZero();
    assertThat(evidence.json()).contains("No missing fields may be inferred");
    verifyNoInteractions(runner);
  }
}
