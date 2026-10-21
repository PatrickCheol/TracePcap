package com.tracepcap.story.dto;

import com.tracepcap.analysis.spi.PacketEvidenceLookup.Coverage;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;

/** Response body for a story Q&A answer */
@Data
@AllArgsConstructor
public class StoryAnswerResponse {
  private String answer;
  private List<String> followUpQuestions;
  private Coverage packetEvidence;
  private String modelUsed;

  public StoryAnswerResponse(String answer, List<String> followUpQuestions) {
    this(answer, followUpQuestions, null, null);
  }
}
