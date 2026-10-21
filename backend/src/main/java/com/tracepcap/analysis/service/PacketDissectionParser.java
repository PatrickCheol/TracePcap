package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.PacketDissectionResponse;
import com.tracepcap.analysis.dto.PacketDissectionResponse.DissectionNode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/** Converts PDML to a bounded protocol tree and proves each mapping against the raw frame. */
@Component
public class PacketDissectionParser {
  private static final int MAX_FIELDS = 20_000;
  private static final int MAX_DEPTH = 64;

  public PacketDissectionResponse parse(
      long frameNumber,
      byte[] pdml,
      byte[] frame,
      Map<String, TsharkFieldRegistry.Metadata> registry,
      List<String> initialWarnings)
      throws IOException {
    try {
      var packets = readDocument(pdml).getElementsByTagName("packet");
      if (packets.getLength() != 1) {
        throw new IOException("The requested original frame was not found in the capture.");
      }
      return parsePacket(frameNumber, (Element) packets.item(0), frame, registry, initialWarnings);
    } catch (SAXException | javax.xml.parsers.ParserConfigurationException e) {
      throw new IOException("Packet decoder returned invalid protocol data.", e);
    }
  }

  /** Batch decoding shares source validation and field semantics with the packet inspector. */
  public List<PacketDissectionResponse> parseBatch(
      byte[] pdml, Map<Long, byte[]> rawFrames, Map<String, TsharkFieldRegistry.Metadata> registry)
      throws IOException {
    try {
      var packets = readDocument(pdml).getElementsByTagName("packet");
      if (packets.getLength() > 24)
        throw new IOException("Detailed evidence batch exceeds 24 frames.");
      List<PacketDissectionResponse> results = new ArrayList<>();
      for (int i = 0; i < packets.getLength(); i++) {
        Element packet = (Element) packets.item(i);
        long number = fieldLong(packet, "frame.number", -1);
        byte[] raw = rawFrames.get(number);
        if (raw == null) throw new IOException("Detailed evidence raw frame is missing.");
        results.add(parsePacket(number, packet, raw, registry, List.of()));
      }
      return List.copyOf(results);
    } catch (SAXException | javax.xml.parsers.ParserConfigurationException e) {
      throw new IOException("Packet decoder returned invalid protocol data.", e);
    }
  }

  private static org.w3c.dom.Document readDocument(byte[] pdml)
      throws IOException, SAXException, javax.xml.parsers.ParserConfigurationException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    factory.setAttribute("http://www.oracle.com/xml/jaxp/properties/maxElementDepth", "128");
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    return factory.newDocumentBuilder().parse(new ByteArrayInputStream(pdml));
  }

  private PacketDissectionResponse parsePacket(
      long frameNumber,
      Element packet,
      byte[] frame,
      Map<String, TsharkFieldRegistry.Metadata> registry,
      List<String> initialWarnings)
      throws IOException {
    var context = new Context(frame, registry, new ArrayList<>(initialWarnings));
    long decodedFrame = fieldLong(packet, "frame.number", frameNumber);
    if (decodedFrame != frameNumber) throw new IOException("Decoder returned a different frame.");
    int originalLength = (int) fieldLong(packet, "frame.len", frame.length);
    int capturedLength = (int) fieldLong(packet, "frame.cap_len", frame.length);
    if (capturedLength != frame.length) {
      throw new IOException("Raw frame size does not match the decoded capture length.");
    }
    if (capturedLength < originalLength) {
      context.warnings.add(
          "This frame was truncated during capture; missing bytes cannot be recovered.");
    }
    boolean reconstructed = hasReassembly(packet);
    List<DissectionNode> protocols = new ArrayList<>();
    for (Node child = packet.getFirstChild(); child != null; child = child.getNextSibling()) {
      if (!(child instanceof Element element) || !element.getTagName().equals("proto")) continue;
      if (element.getAttribute("name").equals("geninfo")) continue;
      String name = element.getAttribute("name");
      boolean applicationReassembled =
          reconstructed && !isTransport(name) && intAttribute(element, "pos", -1) == 0;
      DissectionNode protocol = readNode(element, context, applicationReassembled, false, 0);
      if (protocol != null) protocols.add(protocol);
    }
    if (context.nasDetected) {
      context.warnings.add(
          "NAS fields are decoded from available capture bytes. Ciphered NAS content requires the appropriate keys and security context; it is not automatically decrypted.");
    }
    if (context.hasReassembled) {
      context.warnings.add(
          "Reassembled fields use a reconstructed data source. Their offsets are not highlighted in the original frame.");
    }
    if (context.limited)
      context.warnings.add(
          "The protocol tree exceeded the display field/depth limit and was shortened.");
    if (context.malformed)
      context.warnings.add(
          "The decoder reported malformed or undecodable data; the available fields and raw bytes are retained.");
    return new PacketDissectionResponse(
        frameNumber,
        capturedLength,
        originalLength,
        HexFormat.of().formatHex(frame),
        "TShark / Wireshark dissectors",
        List.copyOf(protocols),
        List.copyOf(context.warnings),
        context.nasDetected);
  }

  private DissectionNode readNode(
      Element element,
      Context context,
      boolean inheritedReassembly,
      boolean inheritedGenerated,
      int depth) {
    if (++context.count > MAX_FIELDS || depth > MAX_DEPTH) {
      context.limited = true;
      return null;
    }
    String name = element.getAttribute("name");
    String label = nonBlank(element.getAttribute("showname"));
    String display = nonBlank(element.getAttribute("show"));
    if (label == null) label = display != null ? display : name;
    if (label == null || label.isBlank()) label = "Unnamed field";
    String lower = name.toLowerCase(Locale.ROOT);
    if (lower.startsWith("nas-5gs") || lower.startsWith("nas_5gs") || lower.startsWith("nas_eps")) {
      context.nasDetected = true;
    }
    if (lower.contains("malformed") || label.contains("[Malformed Packet"))
      context.malformed = true;

    boolean generated = inheritedGenerated || "true".equals(element.getAttribute("generated"));
    boolean reassembled = inheritedReassembly || isReassemblyField(lower);
    int offset = intAttribute(element, "pos", -1);
    int length = intAttribute(element, "size", -1);
    String raw = normalizedHex(element.getAttribute("unmaskedvalue"), length);
    if (raw == null) raw = normalizedHex(element.getAttribute("value"), length);
    var metadata = context.registry.get(name);
    String bitmask = metadata == null ? null : metadata.bitmask();
    String description = NasFieldDescriptions.describe(name);
    if (description == null && metadata != null) description = metadata.description();

    String source;
    Integer safeOffset = null;
    Integer safeLength = null;
    if (reassembled) {
      source = "reassembled";
      safeLength = raw != null && length > 0 ? length : null;
      context.hasReassembled = true;
    } else if (generated || length == 0) {
      source = "generated";
      raw = null;
    } else if (raw != null && matchesFrame(raw, offset, length, context.frame)) {
      source = "frame";
      safeOffset = offset;
      safeLength = length;
    } else {
      // PDML positions can be relative to a decrypted/reassembled tvbuff. Range checking alone
      // would silently highlight unrelated bytes of the original frame.
      source = "unknown";
      safeLength = raw != null && length > 0 ? length : null;
    }

    List<DissectionNode> children = new ArrayList<>();
    for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
      if (child instanceof Element field
          && (field.getTagName().equals("field") || field.getTagName().equals("proto"))) {
        DissectionNode parsed = readNode(field, context, reassembled, generated, depth + 1);
        if (parsed != null) children.add(parsed);
        if (context.count >= MAX_FIELDS) {
          context.limited = true;
          break;
        }
      }
    }
    return new DissectionNode(
        "field-" + context.nextId++,
        name,
        label,
        display,
        raw,
        safeOffset,
        safeLength,
        bitmask,
        source,
        description,
        List.copyOf(children));
  }

  private static boolean matchesFrame(String raw, int offset, int length, byte[] frame) {
    if (offset < 0 || length <= 0 || (long) offset + length > frame.length) return false;
    return raw.equals(HexFormat.of().formatHex(frame, offset, offset + length));
  }

  private static String normalizedHex(String value, int length) {
    if (value == null
        || length <= 0
        || value.length() != (long) length * 2
        || !value.matches("[0-9a-fA-F]+")) return null;
    return value.toLowerCase(Locale.ROOT);
  }

  private static boolean isTransport(String name) {
    return List.of(
            "frame", "eth", "sll", "sll2", "null", "ip", "ipv6", "tcp", "udp", "sctp", "vlan",
            "icmp", "icmpv6")
        .contains(name);
  }

  private static boolean isReassemblyField(String name) {
    return name.endsWith(".reassembled.data")
        || name.endsWith(".segments")
        || name.endsWith(".fragments")
        || name.contains("decrypted");
  }

  private static boolean hasReassembly(Element packet) {
    var fields = packet.getElementsByTagName("field");
    for (int i = 0; i < fields.getLength(); i++) {
      String name = ((Element) fields.item(i)).getAttribute("name");
      if (name.endsWith(".reassembled.length") || name.endsWith(".reassembled.data")) return true;
    }
    return false;
  }

  private static long fieldLong(Element packet, String name, long fallback) {
    var fields = packet.getElementsByTagName("field");
    for (int i = 0; i < fields.getLength(); i++) {
      Element field = (Element) fields.item(i);
      if (!field.getAttribute("name").equals(name)) continue;
      try {
        return Long.parseLong(field.getAttribute("show"));
      } catch (NumberFormatException ignored) {
        return fallback;
      }
    }
    return fallback;
  }

  private static int intAttribute(Element element, String attribute, int fallback) {
    try {
      return Integer.parseInt(element.getAttribute(attribute));
    } catch (NumberFormatException ignored) {
      return fallback;
    }
  }

  private static String nonBlank(String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private static final class Context {
    final byte[] frame;
    final Map<String, TsharkFieldRegistry.Metadata> registry;
    final List<String> warnings;
    int count;
    int nextId;
    boolean nasDetected;
    boolean hasReassembled;
    boolean limited;
    boolean malformed;

    Context(
        byte[] frame, Map<String, TsharkFieldRegistry.Metadata> registry, List<String> warnings) {
      this.frame = frame;
      this.registry = registry;
      this.warnings = warnings;
    }
  }
}
