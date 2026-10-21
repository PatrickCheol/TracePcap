package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.UUID;

/** Lazy Extract-stage observations for grounded Story/Q&A prompts, with explicit coverage. */
public interface PacketEvidenceLookup {
  @io.swagger.v3.oas.annotations.media.Schema(name = "PacketEvidenceCoverage")
  record Coverage(
      String status,
      String selection,
      Long totalFrames,
      int searchFrameLimit,
      int matchedFrames,
      int selectedFrames,
      int decodedFrames,
      int includedFields,
      int omittedFields,
      Long unsearchedFrames,
      List<String> warnings) {}

  record Evidence(String json, Coverage coverage) {}

  /** The question only selects evidence; it never becomes a command or decoder filter. */
  Evidence evidenceFor(UUID fileId, String question);
}
