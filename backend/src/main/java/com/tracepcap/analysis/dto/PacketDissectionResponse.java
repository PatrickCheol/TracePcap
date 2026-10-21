package com.tracepcap.analysis.dto;

import java.util.List;

/** A dissection of one original capture frame, independent of the 64-byte database preview. */
public record PacketDissectionResponse(
    long packetNumber,
    int capturedLength,
    int originalLength,
    String rawHex,
    String decoder,
    List<DissectionNode> protocols,
    List<String> warnings,
    boolean nasDetected) {

  /** Byte positions are present only when their source can be established. */
  public record DissectionNode(
      String id,
      String name,
      String label,
      String displayValue,
      String rawValue,
      Integer byteOffset,
      Integer byteLength,
      String bitmask,
      String source,
      String description,
      List<DissectionNode> children) {}
}
