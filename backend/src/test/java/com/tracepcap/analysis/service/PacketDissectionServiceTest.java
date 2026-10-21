package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.common.exception.StorageException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.service.StorageService;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class PacketDissectionServiceTest {
  final ConversationRepository conversations = mock(ConversationRepository.class);
  final PacketRepository packets = mock(PacketRepository.class);
  final StorageService storage = mock(StorageService.class);
  final TsharkDissectionRunner runner = mock(TsharkDissectionRunner.class);
  final TsharkFieldRegistry registry = mock(TsharkFieldRegistry.class);
  final UUID conversationId = UUID.randomUUID();
  final UUID fileId = UUID.randomUUID();
  final FileEntity file =
      FileEntity.builder().id(fileId).fileSize(2L).minioPath("original.pcap").build();
  final ConversationEntity conversation =
      ConversationEntity.builder().id(conversationId).file(file).build();
  PacketDissectionService service;

  @BeforeEach
  void setUp() {
    service =
        new PacketDissectionService(
            conversations,
            packets,
            storage,
            runner,
            registry,
            new PacketDissectionParser(),
            new ObjectMapper());
    when(conversations.findById(conversationId)).thenReturn(Optional.of(conversation));
  }

  @Test
  void refusesFramesFromAnotherConversationBeforeReadingStorage() {
    var other = ConversationEntity.builder().id(UUID.randomUUID()).file(file).build();
    when(packets.findFirstByFile_IdAndPacketNumber(fileId, 2L))
        .thenReturn(
            Optional.of(PacketEntity.builder().conversation(other).packetNumber(2L).build()));
    assertThatThrownBy(() -> service.dissect(conversationId, 2))
        .isInstanceOf(ResourceNotFoundException.class);
    verifyNoInteractions(storage, runner, registry);
  }

  @Test
  void refusesMissingAndInvalidFramesBeforeReadingStorage() {
    when(packets.findFirstByFile_IdAndPacketNumber(fileId, 2L)).thenReturn(Optional.empty());
    assertThatThrownBy(() -> service.dissect(conversationId, 2))
        .isInstanceOf(ResourceNotFoundException.class);
    assertThatThrownBy(() -> service.dissect(conversationId, -1))
        .isInstanceOf(IllegalArgumentException.class);
    verifyNoInteractions(storage, runner, registry);
  }

  @Test
  void readsOriginalBytesAndKeepsDatabasePreviewOutOfDissection() throws Exception {
    validPacket();
    when(storage.downloadFile("original.pcap"))
        .thenReturn(new ByteArrayInputStream(new byte[] {0, 1}));
    when(registry.fields()).thenReturn(Map.of());
    when(runner.run(anyList(), anyInt(), any()))
        .thenReturn(
            output(
                "<pdml><packet><proto name='data'><field name='data.data' pos='0' size='2' value='7e00'/></proto></packet></pdml>"),
            output("[{\"_source\":{\"layers\":{\"frame_raw\":[\"7e00\",0,2,0,1]}}}]"));
    var result = service.dissect(conversationId, 2);
    assertThat(result.rawHex()).isEqualTo("7e00");
    ArgumentCaptor<java.util.List<String>> arguments =
        ArgumentCaptor.forClass(java.util.List.class);
    verify(runner, times(2)).run(arguments.capture(), anyInt(), any());
    assertThat(arguments.getAllValues().get(0)).contains("-2", "pdml", "frame.number == 2");
    assertThat(Files.exists(Path.of(arguments.getValue().get(3)))).isFalse();
  }

  @Test
  void decoderFailureReturnsExplicitFailureAndDeletesTemporaryCapture() throws Exception {
    validPacket();
    when(storage.downloadFile("original.pcap"))
        .thenReturn(new ByteArrayInputStream(new byte[] {0, 1}));
    when(runner.run(anyList(), anyInt(), any()))
        .thenThrow(new IOException("Packet decoder timed out."));
    assertThatThrownBy(() -> service.dissect(conversationId, 2))
        .isInstanceOf(StorageException.class)
        .hasMessageContaining("timed out");
    ArgumentCaptor<java.util.List<String>> arguments =
        ArgumentCaptor.forClass(java.util.List.class);
    verify(runner).run(arguments.capture(), anyInt(), any());
    assertThat(Files.exists(Path.of(arguments.getValue().get(4)))).isFalse();
  }

  @Test
  void rejectsMalformedRawHex() {
    assertThatThrownBy(
            () ->
                service.parseRawFrame(
                    "[{\"_source\":{\"layers\":{\"frame_raw\":[\"zz\"]}}}]"
                        .getBytes(StandardCharsets.UTF_8)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("invalid raw frame");
  }

  void validPacket() {
    when(packets.findFirstByFile_IdAndPacketNumber(fileId, 2L))
        .thenReturn(
            Optional.of(
                PacketEntity.builder()
                    .conversation(conversation)
                    .packetNumber(2L)
                    .packetSize(2)
                    .payload("ffff")
                    .build()));
  }

  static TsharkDissectionRunner.Output output(String text) {
    return new TsharkDissectionRunner.Output(text.getBytes(StandardCharsets.UTF_8), new byte[0]);
  }
}
