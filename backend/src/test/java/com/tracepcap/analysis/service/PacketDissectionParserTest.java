package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.dto.PacketDissectionResponse.DissectionNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class PacketDissectionParserTest {
  private final PacketDissectionParser parser = new PacketDissectionParser();

  @Test
  void mapsActualNasBitsUsingUnmaskedValueAndRegistryMask() throws Exception {
    String xml =
        """
        <pdml><packet><proto name="nas-5gs" pos="0" size="2" showname="Non-Access-Stratum 5GS">
          <field name="nas_5gs.mm.follow_on_req" pos="1" size="1" show="1"
            showname=".... 1... = Follow-on request: Follow-on request pending" value="1" unmaskedvalue="19"/>
          <field name="nas_5gs.mm.5gs_reg_type" pos="1" size="1" show="1"
            showname=".... .001 = 5GS registration type: Initial registration (1)" value="1" unmaskedvalue="19"/>
        </proto></packet></pdml>""";
    var result =
        parser.parse(
            1,
            xml.getBytes(StandardCharsets.UTF_8),
            new byte[] {0x7e, 0x19},
            Map.of(
                "nas_5gs.mm.follow_on_req",
                new TsharkFieldRegistry.Metadata("0x8", null),
                "nas_5gs.mm.5gs_reg_type",
                new TsharkFieldRegistry.Metadata("0x7", null)),
            List.of());
    assertThat(result.nasDetected()).isTrue();
    assertThat(result.rawHex()).isEqualTo("7e19");
    var followOn = result.protocols().get(0).children().get(0);
    assertThat(followOn.bitmask()).isEqualTo("0x8");
    assertThat(followOn.rawValue()).isEqualTo("19");
    assertThat(followOn.displayValue()).isEqualTo("1");
    assertThat(followOn.byteOffset()).isEqualTo(1);
    assertThat(followOn.source()).isEqualTo("frame");
    assertThat(result.warnings()).anyMatch(w -> w.contains("Ciphered NAS"));
  }

  @Test
  void doesNotMapReassembledOrMismatchingDataOntoOriginalFrame() throws Exception {
    String xml =
        """
        <pdml><packet><proto name="tcp" pos="0" size="1">
          <field name="tcp.reassembled.length" pos="0" size="0" show="1"/>
          <field name="tcp.port" pos="0" size="1" value="bb"/>
        </proto><proto name="http" pos="0" size="1">
          <field name="http.test" pos="0" size="1" value="aa"/>
        </proto></packet></pdml>""";
    var result =
        parser.parse(
            1, xml.getBytes(StandardCharsets.UTF_8), new byte[] {(byte) 0xaa}, Map.of(), List.of());
    DissectionNode mismatch = result.protocols().get(0).children().get(1);
    assertThat(mismatch.source()).isEqualTo("unknown");
    assertThat(mismatch.byteOffset()).isNull();
    var reconstructed = result.protocols().get(1).children().get(0);
    assertThat(reconstructed.source()).isEqualTo("reassembled");
    assertThat(reconstructed.byteOffset()).isNull();
    assertThat(result.warnings()).anyMatch(w -> w.contains("reconstructed data source"));
  }

  @Test
  void reportsTruncationAndMalformedButPreservesAvailableFields() throws Exception {
    String xml =
        """
        <pdml><packet><proto name="frame">
          <field name="frame.len" show="8"/><field name="frame.cap_len" show="2"/>
        </proto><proto name="_ws.malformed" showname="[Malformed Packet]"/></packet></pdml>""";
    var result =
        parser.parse(
            1, xml.getBytes(StandardCharsets.UTF_8), new byte[] {0, 1}, Map.of(), List.of());
    assertThat(result.originalLength()).isEqualTo(8);
    assertThat(result.capturedLength()).isEqualTo(2);
    assertThat(result.warnings()).anyMatch(w -> w.contains("truncated during capture"));
    assertThat(result.warnings()).anyMatch(w -> w.contains("malformed or undecodable"));
    assertThat(result.protocols()).hasSize(2);
  }

  @Test
  void blocksExternalEntitiesAndInvalidFrameOutput() {
    String xxe =
        "<!DOCTYPE pdml [<!ENTITY data SYSTEM 'file:///etc/passwd'>]><pdml><packet>&data;</packet></pdml>";
    assertThatThrownBy(
            () ->
                parser.parse(
                    1, xxe.getBytes(StandardCharsets.UTF_8), new byte[] {0}, Map.of(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("invalid protocol data");
    assertThatThrownBy(
            () ->
                parser.parse(
                    1,
                    "<pdml/>".getBytes(StandardCharsets.UTF_8),
                    new byte[] {0},
                    Map.of(),
                    List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("not found");
  }

  @Test
  void rejectsRawLengthMismatchInsteadOfShowingMisleadingByteOffsets() {
    String xml =
        "<pdml><packet><proto name='frame'><field name='frame.cap_len' show='8'/></proto></packet></pdml>";
    assertThatThrownBy(
            () ->
                parser.parse(
                    1, xml.getBytes(StandardCharsets.UTF_8), new byte[] {0}, Map.of(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("does not match");
  }

  @Test
  void parsesRegistryMaskFromCorrectColumn() throws Exception {
    var fields =
        TsharkFieldRegistry.parse(
            "F\tFollow-on request\tnas_5gs.mm.follow_on_req\tFT_UINT8\tnas-5gs\tBASE_DEC\t0x8\tNAS flag\n"
                + "F\tOther\tother\tFT_UINT8\tip\tBASE_DEC\t0x0\t\n");
    assertThat(fields.get("nas_5gs.mm.follow_on_req").bitmask()).isEqualTo("0x8");
    assertThat(fields.get("nas_5gs.mm.follow_on_req").description()).isEqualTo("NAS flag");
    assertThat(fields).doesNotContainKey("other");
  }

  @Test
  void parsesRealNgapNasSecurityCommandAndMapsHighAndLowNibbleToSameByte() throws Exception {
    byte[] pdml = fixture("nas-security-mode-frame4.pdml");
    byte[] raw = fixtureRaw("nas-security-mode-frame4.jsonraw");
    var result =
        parser.parse(
            4,
            pdml,
            raw,
            Map.of(
                "nas_5gs.mm.nas_sec_algo_enc", new TsharkFieldRegistry.Metadata("0xf0", null),
                "nas_5gs.mm.nas_sec_algo_ip", new TsharkFieldRegistry.Metadata("0xf", null)),
            List.of());
    var cipher =
        flatten(result.protocols())
            .filter(n -> n.name().equals("nas_5gs.mm.nas_sec_algo_enc"))
            .findFirst()
            .orElseThrow();
    var integrity =
        flatten(result.protocols())
            .filter(n -> n.name().equals("nas_5gs.mm.nas_sec_algo_ip"))
            .findFirst()
            .orElseThrow();
    assertThat(result.nasDetected()).isTrue();
    assertThat(cipher.source()).isEqualTo("frame");
    assertThat(cipher.byteOffset()).isEqualTo(90);
    assertThat(cipher.rawValue()).isEqualTo("22");
    assertThat(cipher.displayValue()).isEqualTo("2");
    assertThat(cipher.bitmask()).isEqualTo("0xf0");
    assertThat(integrity.byteOffset()).isEqualTo(cipher.byteOffset());
    assertThat(integrity.bitmask()).isEqualTo("0xf");
  }

  @Test
  void realReassembledHttpMethodNeverHighlightsOriginalEthernetBytes() throws Exception {
    var result =
        parser.parse(
            5,
            fixture("http-reassembled-frame5.pdml"),
            fixtureRaw("http-reassembled-frame5.jsonraw"),
            Map.of(),
            List.of());
    var method =
        flatten(result.protocols())
            .filter(n -> n.name().equals("http.request.method"))
            .findFirst()
            .orElseThrow();
    assertThat(method.source()).isEqualTo("reassembled");
    assertThat(method.rawValue()).isEqualTo("474554");
    assertThat(method.byteOffset()).isNull();
    assertThat(method.byteLength()).isEqualTo(3);
  }

  static Stream<DissectionNode> flatten(List<DissectionNode> nodes) {
    return nodes.stream().flatMap(n -> Stream.concat(Stream.of(n), flatten(n.children())));
  }

  static byte[] fixture(String name) throws IOException {
    try (var input = PacketDissectionParserTest.class.getResourceAsStream("/dissection/" + name)) {
      if (input == null) throw new IOException("Missing fixture " + name);
      return input.readAllBytes();
    }
  }

  static byte[] fixtureRaw(String name) throws IOException {
    var json = new ObjectMapper().readTree(fixture(name));
    return HexFormat.of()
        .parseHex(json.get(0).path("_source").path("layers").path("frame_raw").get(0).asText());
  }
}
