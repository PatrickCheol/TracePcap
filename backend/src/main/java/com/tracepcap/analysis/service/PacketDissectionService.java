package com.tracepcap.analysis.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.dto.PacketDissectionResponse;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.common.exception.StorageException;
import com.tracepcap.file.service.StorageService;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** On-demand, local-only decoding of an authorized conversation's original capture frame. */
@Service
public class PacketDissectionService {
  static final long MAX_CAPTURE_BYTES = 500L * 1024 * 1024;
  private static final int MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
  private static final int MAX_FRAME_BYTES = 2 * 1024 * 1024;
  private final ConversationRepository conversations;
  private final PacketRepository packets;
  private final StorageService storage;
  private final TsharkDissectionRunner runner;
  private final TsharkFieldRegistry registry;
  private final PacketDissectionParser parser;
  private final ObjectMapper mapper;
  private final Semaphore decoderSlots = new Semaphore(2);

  public PacketDissectionService(
      ConversationRepository conversations,
      PacketRepository packets,
      StorageService storage,
      TsharkDissectionRunner runner,
      TsharkFieldRegistry registry,
      PacketDissectionParser parser,
      ObjectMapper mapper) {
    this.conversations = conversations;
    this.packets = packets;
    this.storage = storage;
    this.runner = runner;
    this.registry = registry;
    this.parser = parser;
    this.mapper = mapper;
  }

  @Transactional(readOnly = true)
  public PacketDissectionResponse dissect(UUID conversationId, long packetNumber) {
    if (packetNumber < 1) throw new IllegalArgumentException("Frame number must be positive.");
    ConversationEntity conversation =
        conversations
            .findById(conversationId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Conversation not found: " + conversationId));
    var file = conversation.getFile();
    var packet =
        packets
            .findFirstByFile_IdAndPacketNumber(file.getId(), packetNumber)
            .filter(
                p ->
                    p.getConversation() != null
                        && conversationId.equals(p.getConversation().getId()))
            .orElseThrow(
                () -> new ResourceNotFoundException("Frame does not belong to this conversation."));
    // Association is checked before touching the original capture. Do not trust caller-supplied
    // storage paths or decode a frame from another conversation in the same uploaded file.
    if (file.getMinioPath() == null || file.getMinioPath().isBlank()) {
      throw new ResourceNotFoundException("The original capture is no longer available.");
    }
    if (file.getFileSize() != null && file.getFileSize() > MAX_CAPTURE_BYTES) {
      throw new IllegalArgumentException("Capture exceeds the 500 MB limit for packet dissection.");
    }
    if (packet.getPacketSize() != null && packet.getPacketSize() > MAX_FRAME_BYTES) {
      throw new IllegalArgumentException("Frame exceeds the 2 MB limit for packet dissection.");
    }
    if (!decoderSlots.tryAcquire()) {
      throw new StorageException("Packet decoders are busy. Please try again shortly.");
    }
    Path temporary = null;
    try {
      temporary = Files.createTempFile("packet-dissection-", ".pcap");
      try (InputStream input = storage.downloadFile(file.getMinioPath());
          var output = Files.newOutputStream(temporary)) {
        byte[] buffer = new byte[65_536];
        long copied = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
          copied += read;
          if (copied > MAX_CAPTURE_BYTES)
            throw new IOException("Capture exceeds the 500 MB dissection limit.");
          output.write(buffer, 0, read);
        }
      }
      List<String> command =
          List.of(
              "tshark",
              "-n",
              "-2",
              "-r",
              temporary.toString(),
              "-c",
              Long.toString(packetNumber),
              "-Y",
              "frame.number == " + packetNumber,
              "-T",
              "pdml");
      byte[] pdml = runner.run(command, MAX_OUTPUT_BYTES, Duration.ofSeconds(30)).stdout();
      byte[] rawOutput =
          runner
              .run(
                  List.of(
                      "tshark",
                      "-n",
                      "-r",
                      temporary.toString(),
                      "-c",
                      Long.toString(packetNumber),
                      "-Y",
                      "frame.number == " + packetNumber,
                      "-T",
                      "jsonraw",
                      "-j",
                      "frame"),
                  MAX_OUTPUT_BYTES,
                  Duration.ofSeconds(30))
              .stdout();
      byte[] raw = parseRawFrame(rawOutput);
      List<String> warnings = new ArrayList<>();
      Map<String, TsharkFieldRegistry.Metadata> fields;
      try {
        fields = registry.fields();
      } catch (IOException e) {
        fields = Map.of();
        warnings.add(
            "Decoder field metadata is unavailable; bit masks and some field descriptions are omitted.");
      }
      return parser.parse(packetNumber, pdml, raw, fields, warnings);
    } catch (IOException e) {
      throw new StorageException(e.getMessage(), e);
    } finally {
      decoderSlots.release();
      if (temporary != null) {
        try {
          Files.deleteIfExists(temporary);
        } catch (IOException ignored) {
          temporary.toFile().deleteOnExit();
        }
      }
    }
  }

  byte[] parseRawFrame(byte[] json) throws IOException {
    JsonNode root = mapper.readTree(json);
    if (!root.isArray() || root.size() != 1) {
      throw new IOException("The original frame was not found in this capture.");
    }
    JsonNode rawNode = root.get(0).path("_source").path("layers").path("frame_raw").path(0);
    String hex = rawNode.isTextual() ? rawNode.asText() : "";
    if (hex.isEmpty() || hex.length() > (long) MAX_FRAME_BYTES * 2 || hex.length() % 2 != 0) {
      throw new IOException(
          "The decoder did not return a valid complete raw frame (maximum 2 MB).");
    }
    try {
      return HexFormat.of().parseHex(hex);
    } catch (IllegalArgumentException e) {
      throw new IOException("The decoder returned invalid raw frame bytes.", e);
    }
  }
}
