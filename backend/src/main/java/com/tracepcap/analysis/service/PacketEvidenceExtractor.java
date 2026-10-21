package com.tracepcap.analysis.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.dto.PacketDissectionResponse;
import com.tracepcap.analysis.dto.PacketDissectionResponse.DissectionNode;
import com.tracepcap.analysis.spi.PacketEvidenceLookup;
import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

/** Bounded, lazy Extract-stage protocol observations shared by Story and follow-up questions. */
@Service
public class PacketEvidenceExtractor implements PacketEvidenceLookup {
  static final int SEARCH_FRAME_LIMIT = 100_000;
  static final int MAX_FRAMES = 24;
  static final int MAX_FIELDS = 400;
  static final int MAX_PROMPT_CHARS = 64_000;
  private static final long MAX_CAPTURE_BYTES = PacketDissectionService.MAX_CAPTURE_BYTES;
  private static final long DEADLINE_NANOS = Duration.ofSeconds(50).toNanos();
  private static final Pattern FRAME_QUERY =
      Pattern.compile("(?i)(?:frame|packet|프레임|패킷|#)\\s*#?\\s*(\\d{1,9})");
  private static final Set<String> TRANSPORT =
      Set.of("frame", "eth", "ip", "ipv6", "tcp", "udp", "sctp", "sll", "sll2");
  private final FileRepository files;
  private final PacketLookup packets;
  private final StorageService storage;
  private final TsharkDissectionRunner runner;
  private final TsharkFieldRegistry registry;
  private final PacketDissectionParser parser;
  private final ObjectMapper mapper;
  private final Semaphore slots = new Semaphore(1);

  public PacketEvidenceExtractor(
      FileRepository files,
      PacketLookup packets,
      StorageService storage,
      TsharkDissectionRunner runner,
      TsharkFieldRegistry registry,
      PacketDissectionParser parser,
      ObjectMapper mapper) {
    this.files = files;
    this.packets = packets;
    this.storage = storage;
    this.runner = runner;
    this.registry = registry;
    this.parser = parser;
    this.mapper = mapper;
  }

  @Override
  public Evidence evidenceFor(UUID fileId, String question) {
    Selection selection = selection(question);
    FileEntity file = files.findById(fileId).orElse(null);
    Long total =
        file != null && file.getPacketCount() != null ? file.getPacketCount().longValue() : null;
    if (file == null || file.getMinioPath() == null || file.getMinioPath().isBlank()) {
      return unavailable(
          selection.label,
          total,
          "Original capture is unavailable; detailed protocol evidence was not inspected.");
    }
    if (file.getFileSize() != null && file.getFileSize() > MAX_CAPTURE_BYTES) {
      return unavailable(
          selection.label, total, "Original capture exceeds the 500 MB detailed-evidence limit.");
    }
    if (!slots.tryAcquire())
      return unavailable(
          selection.label,
          total,
          "Detailed-evidence extractor is busy; no packet detail was supplied for this request.");
    long deadline = System.nanoTime() + DEADLINE_NANOS;
    Path capture = null;
    try {
      capture = Files.createTempFile("story-packet-evidence-", ".pcap");
      try (var input = storage.downloadFile(file.getMinioPath());
          var output = Files.newOutputStream(capture)) {
        byte[] buffer = new byte[65_536];
        long copied = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
          copied += read;
          if (copied > MAX_CAPTURE_BYTES)
            throw new IOException("Capture exceeds the 500 MB evidence limit.");
          remaining(deadline);
          output.write(buffer, 0, read);
        }
      }
      List<String> candidateOutput =
          new ArrayList<>(List.of("-T", "fields", "-e", "frame.number", "-e", "frame.protocols"));
      if (selection.identity) candidateOutput.addAll(List.of("-e", "nas_5gs.mm.type_id"));
      byte[] candidates =
          run(
              capture,
              SEARCH_FRAME_LIMIT,
              selection.filter,
              candidateOutput,
              16 * 1024 * 1024,
              deadline);
      List<Candidate> matches = candidates(candidates);
      List<Candidate> selected = select(matches, selection.identity);
      if (selected.isEmpty()) {
        var warnings = new ArrayList<String>();
        warnings.add(
            "No matching detailed protocol fields were observed within the searched capture range. This is not proof that the protocol or identity is absent from the network.");
        return assemble(fileId, selection, total, matches.size(), List.of(), List.of(), warnings);
      }
      int lastFrame = (int) selected.stream().mapToLong(Candidate::number).max().orElse(1);
      String frameFilter =
          "frame.number in {"
              + selected.stream().map(c -> Long.toString(c.number)).collect(Collectors.joining(" "))
              + "}";
      byte[] pdml =
          run(capture, lastFrame, frameFilter, List.of("-T", "pdml"), 12 * 1024 * 1024, deadline);
      byte[] raw =
          run(
              capture,
              lastFrame,
              frameFilter,
              List.of("-T", "jsonraw", "-j", "frame"),
              16 * 1024 * 1024,
              deadline);
      Map<Long, byte[]> rawFrames = rawFrames(raw, selected);
      List<String> warnings = new ArrayList<>();
      Map<String, TsharkFieldRegistry.Metadata> fields;
      try {
        fields = registry.fields(remaining(deadline));
      } catch (IOException e) {
        fields = Map.of();
        warnings.add("Decoder bit-mask metadata was unavailable; no missing mask was inferred.");
      }
      List<PacketDissectionResponse> decoded = parser.parseBatch(pdml, rawFrames, fields);
      if (decoded.size() != selected.size())
        warnings.add("Some selected frames were not returned by the decoder.");
      return assemble(fileId, selection, total, matches.size(), selected, decoded, warnings);
    } catch (Exception e) {
      return unavailable(
          selection.label,
          total,
          "Detailed protocol extraction did not complete (capture access, decoder limit, or timeout). No missing fields may be inferred.");
    } finally {
      slots.release();
      if (capture != null) {
        try {
          Files.deleteIfExists(capture);
        } catch (IOException ignored) {
          capture.toFile().deleteOnExit();
        }
      }
    }
  }

  private byte[] run(
      Path capture, int count, String filter, List<String> output, int maxBytes, long deadline)
      throws IOException {
    List<String> command =
        new ArrayList<>(
            List.of(
                "tshark",
                "-n",
                "-2",
                "-r",
                capture.toString(),
                "-c",
                Integer.toString(count),
                "-Y",
                filter));
    command.addAll(output);
    return runner.run(command, maxBytes, remaining(deadline)).stdout();
  }

  private static Duration remaining(long deadline) throws IOException {
    long left = deadline - System.nanoTime();
    if (left <= 0) throw new IOException("Detailed evidence time budget exhausted.");
    return Duration.ofNanos(Math.min(left, Duration.ofSeconds(20).toNanos()));
  }

  static List<Candidate> candidates(byte[] output) {
    List<Candidate> results = new ArrayList<>();
    for (String line : new String(output, StandardCharsets.UTF_8).split("\\R")) {
      String[] columns = line.split("\\t", -1);
      try {
        long number = Long.parseLong(columns[0]);
        if (number < 1 || number > SEARCH_FRAME_LIMIT) continue;
        results.add(
            new Candidate(
                number,
                columns.length > 1 ? columns[1] : "unknown",
                columns.length > 2 && Arrays.asList(columns[2].split(",")).contains("1")));
      } catch (NumberFormatException ignored) {
        /* Non-data decoder lines cannot become a filter. */
      }
    }
    return results;
  }

  static List<Candidate> select(List<Candidate> matches, boolean identity) {
    if (identity)
      return matches.stream()
          .sorted(
              Comparator.comparing(Candidate::identity)
                  .reversed()
                  .thenComparingLong(Candidate::number))
          .limit(MAX_FRAMES)
          .toList();
    // Round robin by decoded protocol preserves minority protocols in a noisy capture.
    Map<String, ArrayDeque<Candidate>> groups = new LinkedHashMap<>();
    matches.stream()
        .sorted(Comparator.comparingInt(c -> c.protocols.contains("nas") ? 0 : 1))
        .forEach(
            c -> {
              String[] path = c.protocols.split(":");
              groups.computeIfAbsent(path[path.length - 1], ignored -> new ArrayDeque<>()).add(c);
            });
    List<Candidate> selected = new ArrayList<>();
    while (selected.size() < MAX_FRAMES) {
      boolean added = false;
      for (var group : groups.values()) {
        if (group.isEmpty()) continue;
        selected.add(group.removeFirst());
        added = true;
        if (selected.size() == MAX_FRAMES) break;
      }
      if (!added) break;
    }
    return List.copyOf(selected);
  }

  private Map<Long, byte[]> rawFrames(byte[] json, List<Candidate> selected) throws IOException {
    JsonNode entries = mapper.readTree(json);
    if (entries == null || !entries.isArray() || entries.size() > MAX_FRAMES)
      throw new IOException("Invalid batch raw frames.");
    Set<Long> allowed = selected.stream().map(Candidate::number).collect(Collectors.toSet());
    Map<Long, byte[]> result = new HashMap<>();
    // jsonraw frame.number_raw is an encoded presentation field, so use the selected frame
    // order: tshark emits original frame order independent of our selection ranking.
    List<Long> numbers = allowed.stream().sorted().toList();
    if (entries.size() != numbers.size())
      throw new IOException("Selected/raw frame count mismatch.");
    for (int i = 0; i < entries.size(); i++) {
      String hex =
          entries.get(i).path("_source").path("layers").path("frame_raw").path(0).asText("");
      if (hex.isEmpty() || hex.length() > 4 * 1024 * 1024 || hex.length() % 2 != 0)
        throw new IOException("Invalid raw frame size.");
      try {
        result.put(numbers.get(i), HexFormat.of().parseHex(hex));
      } catch (IllegalArgumentException e) {
        throw new IOException("Invalid raw frame bytes.", e);
      }
    }
    return result;
  }

  private Evidence assemble(
      UUID fileId,
      Selection selection,
      Long total,
      int matched,
      List<Candidate> selected,
      List<PacketDissectionResponse> decoded,
      List<String> warnings)
      throws IOException {
    List<Map<String, Object>> frames = new ArrayList<>();
    List<FieldRow> fields = new ArrayList<>();
    Set<String> uniqueWarnings = new LinkedHashSet<>(warnings);
    for (var packet : decoded) {
      String conversation =
          packets
              .conversationIdForFrame(fileId, packet.packetNumber())
              .map(UUID::toString)
              .orElse(null);
      Map<String, Object> frame = new LinkedHashMap<>();
      frame.put("packetNumber", packet.packetNumber());
      frame.put("conversationId", conversation);
      frame.put("capturedLength", packet.capturedLength());
      frame.put("originalLength", packet.originalLength());
      frame.put(
          "protocols",
          packet.protocols().stream().limit(24).map(n -> shortened(n.name(), 64)).toList());
      if (packet.protocols().size() > 24)
        uniqueWarnings.add("Some frame protocol names were omitted by the evidence budget.");
      frames.add(frame);
      uniqueWarnings.addAll(packet.warnings());
      collect(packet.protocols(), "", packet.packetNumber(), conversation, selection, fields);
    }
    fields.sort(
        Comparator.comparingInt(FieldRow::rank).reversed().thenComparingLong(FieldRow::frame));
    List<Map<String, Object>> included = new ArrayList<>();
    int chars = 0;
    for (var field : fields) {
      if (included.size() >= MAX_FIELDS) break;
      int length = mapper.writeValueAsString(field.data).length();
      if (chars + length > MAX_PROMPT_CHARS - 8_000) continue;
      included.add(field.data);
      chars += length;
    }
    int omitted = fields.size() - included.size();
    Long unsearched = total == null ? null : Math.max(0, total - SEARCH_FRAME_LIMIT);
    boolean partial =
        total == null
            || unsearched > 0
            || matched > decoded.size()
            || omitted > 0
            || !uniqueWarnings.isEmpty();
    if (matched > decoded.size())
      uniqueWarnings.add(
          "Only "
              + decoded.size()
              + " of "
              + matched
              + " matching frames were decoded; the remaining matches were omitted from the prompt.");
    if (omitted > 0)
      uniqueWarnings.add(
          "Some decoded fields were omitted by the prompt field/character budget; see omittedFields.");
    if (unsearched == null || unsearched > 0)
      uniqueWarnings.add(
          "Candidate search is limited to the first 100000 frames; absence in this evidence is not absence from the capture.");
    Coverage coverage =
        new Coverage(
            partial ? "partial" : "complete",
            selection.label,
            total,
            SEARCH_FRAME_LIMIT,
            matched,
            selected.size(),
            decoded.size(),
            included.size(),
            omitted,
            unsearched,
            List.copyOf(uniqueWarnings));
    Map<String, Object> document = new LinkedHashMap<>();
    document.put("fileId", fileId);
    document.put("coverage", coverage);
    document.put("frames", frames);
    document.put("fields", included);
    String json = mapper.writeValueAsString(document);
    while (json.length() > MAX_PROMPT_CHARS && !included.isEmpty()) {
      included.remove(included.size() - 1);
      uniqueWarnings.add(
          "Some decoded fields were omitted by the prompt field/character budget; see omittedFields.");
      coverage =
          new Coverage(
              "partial",
              selection.label,
              total,
              SEARCH_FRAME_LIMIT,
              matched,
              selected.size(),
              decoded.size(),
              included.size(),
              fields.size() - included.size(),
              unsearched,
              List.copyOf(uniqueWarnings));
      document.put("coverage", coverage);
      json = mapper.writeValueAsString(document);
    }
    if (json.length() > MAX_PROMPT_CHARS)
      throw new IOException("Detailed evidence metadata exceeds prompt budget.");
    return new Evidence(json, coverage);
  }

  private void collect(
      List<DissectionNode> nodes,
      String parent,
      long frame,
      String conversation,
      Selection selection,
      List<FieldRow> results) {
    for (var node : nodes) {
      String component = node.name().isBlank() ? node.label() : node.name();
      String path = parent.isEmpty() ? component : parent + " > " + component;
      if (node.displayValue() != null || node.rawValue() != null) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("packetNumber", frame);
        data.put("conversationId", conversation);
        data.put("path", shortened(path, 450));
        data.put("name", node.name());
        data.put("label", shortened(node.label(), 220));
        data.put("value", shortened(node.displayValue(), 400));
        data.put("rawValue", shortened(node.rawValue(), 256));
        data.put("byteOffset", node.byteOffset());
        data.put("byteLength", node.byteLength());
        data.put("bitmask", node.bitmask());
        data.put("source", node.source());
        data.put("description", shortened(node.description(), 220));
        boolean truncated =
            (node.displayValue() != null && node.displayValue().length() > 400)
                || (node.rawValue() != null && node.rawValue().length() > 256)
                || path.length() > 450;
        data.put("valueTruncated", truncated);
        int rank = relevance(node, path, selection);
        results.add(new FieldRow(frame, rank, data));
      }
      collect(node.children(), path, frame, conversation, selection, results);
    }
  }

  static int relevance(DissectionNode node, String path, Selection selection) {
    String text = (path + " " + node.label()).toLowerCase(Locale.ROOT);
    int rank = 0;
    if (text.contains("5gs mobile identity")
        || text.contains("5gs_mobile_identity")
        || text.contains("suci")
        || text.contains("supi")) rank += 100;
    if (selection.identity
        && (node.name().equals("e212.mcc")
            || node.name().equals("e212.mnc")
            || node.name().equals("nas_5gs.mm.type_id"))) rank += 150;
    if (node.name().startsWith("nas_") || node.name().startsWith("ngap.")) rank += 20;
    String protocol = node.name().split("\\.")[0];
    if (!TRANSPORT.contains(protocol)) rank += 10;
    for (String term : selection.terms) if (text.contains(term)) rank += 50;
    if (node.name().contains("message_type") || node.name().contains("security_header")) rank += 20;
    return rank;
  }

  static Selection selection(String question) {
    String lower = question == null ? "" : question.toLowerCase(Locale.ROOT);
    List<String> terms =
        Arrays.stream(lower.split("[^\\p{L}\\p{N}_.-]+"))
            .filter(s -> s.length() > 2)
            .limit(12)
            .toList();
    var frame = FRAME_QUERY.matcher(lower);
    if (frame.find()) {
      long number = Long.parseLong(frame.group(1));
      return new Selection(
          "Requested frame " + number + " (within search range)",
          "frame.number == " + number,
          false,
          terms);
    }
    boolean identity =
        lower.contains("suci")
            || lower.contains("supi")
            || lower.contains("가입자")
            || lower.contains("mobile identity");
    if (identity)
      return new Selection("SUCI / 5GS identity and protected NAS context", "nas-5gs", true, terms);
    List<String> protocols = new ArrayList<>();
    for (String protocol :
        List.of(
            "http", "dns", "ftp", "tls", "ngap", "pfcp", "sctp", "tcp", "udp", "quic", "smb", "ssh",
            "icmp")) {
      if (lower.contains(protocol)) protocols.add(protocol);
    }
    if (lower.contains("nas") || lower.contains("5g")) protocols.add("nas-5gs");
    if (!protocols.isEmpty())
      return new Selection(
          "Question-related protocols: " + String.join(", ", protocols),
          String.join(" || ", protocols),
          false,
          terms);
    return new Selection(
        "Representative frames, round robin across decoded protocols", "frame", false, terms);
  }

  private Evidence unavailable(String selection, Long total, String warning) {
    Coverage coverage =
        new Coverage(
            "unavailable",
            selection,
            total,
            SEARCH_FRAME_LIMIT,
            0,
            0,
            0,
            0,
            0,
            total,
            List.of(warning));
    try {
      return new Evidence(
          mapper.writeValueAsString(Map.of("coverage", coverage, "fields", List.of())), coverage);
    } catch (IOException e) {
      throw new IllegalStateException("Cannot serialize evidence coverage.", e);
    }
  }

  private static String shortened(String value, int max) {
    return value == null || value.length() <= max
        ? value
        : value.substring(0, max) + " [TRUNCATED]";
  }

  record Candidate(long number, String protocols, boolean identity) {}

  record Selection(String label, String filter, boolean identity, List<String> terms) {}

  record FieldRow(long frame, int rank, Map<String, Object> data) {}
}
