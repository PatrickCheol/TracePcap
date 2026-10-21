package com.tracepcap.analysis.service;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Real synthetic decoder output wired to deterministic mocks; never calls an external model. */
public final class PacketEvidenceFixture {
  public static PacketEvidenceExtractor identity(UUID fileId, UUID conversationId)
      throws Exception {
    return extractor(
        fileId, conversationId, "nas-identity-frame1", 1, "eth:ip:sctp:ngap:nas-5gs", "1");
  }

  public static PacketEvidenceExtractor http(UUID fileId, UUID conversationId) throws Exception {
    return extractor(fileId, conversationId, "http-reassembled-frame5", 5, "eth:ip:tcp:http", "");
  }

  static PacketEvidenceExtractor extractor(
      UUID fileId,
      UUID conversationId,
      String fixture,
      long number,
      String protocols,
      String identity)
      throws Exception {
    byte[] pdml = bytes(fixture + ".pdml");
    byte[] raw = bytes(fixture + ".jsonraw");
    return extractor(fileId, conversationId, number, protocols, identity, pdml, raw);
  }

  static PacketEvidenceExtractor extractor(
      UUID fileId,
      UUID conversationId,
      long number,
      String protocols,
      String identity,
      byte[] pdml,
      byte[] raw)
      throws Exception {
    FileRepository files = mock(FileRepository.class);
    when(files.findById(fileId))
        .thenReturn(
            Optional.of(
                FileEntity.builder()
                    .id(fileId)
                    .minioPath("synthetic-only.pcap")
                    .fileSize(512L)
                    .packetCount((int) number)
                    .build()));
    PacketLookup packets = mock(PacketLookup.class);
    when(packets.conversationIdForFrame(fileId, number)).thenReturn(Optional.of(conversationId));
    StorageService storage = mock(StorageService.class);
    when(storage.downloadFile("synthetic-only.pcap"))
        .thenAnswer(ignored -> new ByteArrayInputStream(new byte[] {0, 1}));
    TsharkDissectionRunner runner = mock(TsharkDissectionRunner.class);
    when(runner.run(anyList(), anyInt(), any()))
        .thenAnswer(
            invocation -> {
              List<String> arguments = invocation.getArgument(0);
              byte[] output =
                  arguments.contains("pdml")
                      ? pdml
                      : arguments.contains("jsonraw")
                          ? raw
                          : (number + "\t" + protocols + "\t" + identity + "\n")
                              .getBytes(StandardCharsets.UTF_8);
              return new TsharkDissectionRunner.Output(output, new byte[0]);
            });
    TsharkFieldRegistry registry = mock(TsharkFieldRegistry.class);
    when(registry.fields(any(Duration.class)))
        .thenReturn(
            Map.of(
                "nas_5gs.mm.type_id", new TsharkFieldRegistry.Metadata("0x7", null),
                "nas_5gs.mm.suci.scheme_id", new TsharkFieldRegistry.Metadata("0xf", null)));
    return new PacketEvidenceExtractor(
        files,
        packets,
        storage,
        runner,
        registry,
        new PacketDissectionParser(),
        new ObjectMapper());
  }

  static byte[] bytes(String name) throws Exception {
    try (var stream = PacketEvidenceFixture.class.getResourceAsStream("/dissection/" + name)) {
      if (stream == null) throw new IllegalStateException("Missing synthetic fixture: " + name);
      return stream.readAllBytes();
    }
  }

  private PacketEvidenceFixture() {}
}
