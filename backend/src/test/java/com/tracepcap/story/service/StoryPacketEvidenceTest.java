package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.service.PacketEvidenceExtractor;
import com.tracepcap.analysis.service.PacketEvidenceFixture;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup.CaptureSummary;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.config.LlmConfig;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.knowledge.service.CaseKnowledgeService;
import com.tracepcap.knowledge.service.InvestigationOrchestrator;
import com.tracepcap.knowledge.service.StandardQuestionService;
import com.tracepcap.story.dto.StoryAggregates;
import com.tracepcap.story.dto.StoryQuestionRequest;
import com.tracepcap.story.entity.StoryEntity;
import com.tracepcap.story.repository.StoryRepository;
import com.tracepcap.timeline.service.TimelineService;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/** Protocol facts from synthetic TShark output must reach the actual mocked LLM call. */
class StoryPacketEvidenceTest {
  final UUID fileId = UUID.randomUUID();
  final UUID conversationId = UUID.randomUUID();
  final UUID storyId = UUID.randomUUID();
  final StoryRepository stories = mock(StoryRepository.class);
  final FileRepository files = mock(FileRepository.class);
  final AnalysisSummaryLookup summaries = mock(AnalysisSummaryLookup.class);
  final ConversationLookup conversations = mock(ConversationLookup.class);
  final LlmClient llm = mock(LlmClient.class);
  final LlmConfig config = new LlmConfig();
  final StoryAggregatesService aggregates = mock(StoryAggregatesService.class);
  final InvestigationOrchestrator orchestrator = mock(InvestigationOrchestrator.class);
  PacketEvidenceExtractor evidence;
  StoryService service;

  @BeforeEach
  void setup() throws Exception {
    when(orchestrator.investigatedBoard(fileId))
        .thenReturn(
            new com.tracepcap.knowledge.spi.CaseKnowledge(fileId, List.of(), List.of(), List.of()));
    evidence = spy(PacketEvidenceFixture.identity(fileId, conversationId));
    var api = new LlmConfig.ApiConfig();
    api.setModel("test-model-only");
    config.setApi(api);
    var aggregate =
        StoryAggregates.builder().beaconCandidates(List.of()).topExternalAsns(List.of()).build();
    when(aggregates.compute(eq(fileId), anyList(), anyLong())).thenReturn(aggregate);
    when(summaries.summaryFor(fileId))
        .thenReturn(
            Optional.of(
                new CaptureSummary(
                    1, 138, LocalDateTime.now(), LocalDateTime.now(), 0L, Map.of())));
    when(files.findById(fileId))
        .thenReturn(
            Optional.of(
                FileEntity.builder()
                    .id(fileId)
                    .fileName("synthetic.pcap")
                    .fileSize(512L)
                    .packetCount(1)
                    .build()));
    when(stories.findById(storyId))
        .thenReturn(
            Optional.of(
                StoryEntity.builder()
                    .id(storyId)
                    .fileId(fileId)
                    .status(StoryEntity.StoryStatus.COMPLETED)
                    .content(
                        "{\"narrative\":[{\"content\":\"Old LLM answer: NAS detail and SUCI unavailable\"}]}")
                    .build()));
    service =
        new StoryService(
            stories,
            files,
            summaries,
            conversations,
            llm,
            config,
            new ObjectMapper(),
            aggregates,
            mock(FindingsService.class),
            mock(NarratorRunner.class),
            mock(InvestigationService.class),
            mock(InvestigationTools.class),
            mock(TimelineService.class),
            mock(StandardQuestionService.class),
            mock(CaseKnowledgeService.class),
            orchestrator,
            evidence);
  }

  @Test
  void existingStoryQuestionsGetFreshSuciFieldsIncludingPlmnAndStaleAnswerGuard() {
    when(llm.generateCompletion(anyString(), anyString()))
        .thenReturn("{\"answer\":\"Synthetic answer\",\"followUpQuestions\":[]}");
    var history = new StoryQuestionRequest.HistoryEntry();
    history.setRole("assistant");
    history.setText("Earlier answer said SUCI details unavailable.");
    var answer = service.askQuestion(storyId, "SUCI 상세필드는?", List.of(history));
    service.askQuestion(storyId, "SUCI 상세필드는?", List.of());
    var system = ArgumentCaptor.forClass(String.class);
    var prompt = ArgumentCaptor.forClass(String.class);
    verify(llm, times(2)).generateCompletion(system.capture(), prompt.capture());
    assertProtocolFacts(prompt.getValue());
    assertThat(system.getValue())
        .contains(
            "UNTRUSTED DATA",
            "Output language: Korean (ko-KR)",
            "takes precedence over stored LLM story",
            "Never manufacture a SUCI",
            "encrypted scheme output");
    assertThat(prompt.getAllValues().get(0))
        .contains("Earlier answer said SUCI details unavailable");
    verify(evidence, times(2)).evidenceFor(fileId, "SUCI 상세필드는?");
    assertThat(answer.getPacketEvidence().decodedFrames()).isEqualTo(1);
    assertThat(answer.getModelUsed()).isEqualTo("test-model-only");
  }

  @Test
  void generatedStoryIncludesDecodedFactsInFinalNarrativePrompt() {
    generate(null);
  }

  @Test
  void customPromptRetryAlsoIncludesFreshProtocolEvidence() {
    generate("User-edited narrative prompt");
  }

  @Test
  void koreanNarrativeAndTimelineSurviveNullOptionalReferences() {
    when(llm.generateCompletion(anyString(), anyString())).thenReturn("""
        {"narrative":[{"title":"SUCI 분석 요약","content":"프레임 1의 MCC는 001입니다.",
          "type":"summary","relatedData":null}],"highlights":[],
         "timeline":[{"title":"등록 요청 관측","description":"SUCI 필드가 확인되었습니다.",
          "timestamp":null,"type":"normal","relatedData":null}],
         "suggestedQuestions":["보호 방식은 무엇인가요?"]}
        """);
    var answer = service.generateStory(fileId, "SUCI 분석", "User-edited English prompt");
    assertThat(answer.getNarrative()).hasSize(1);
    assertThat(answer.getNarrative().get(0).getTitle()).isEqualTo("SUCI 분석 요약");
    assertThat(answer.getNarrative().get(0).getContent()).contains("MCC는 001");
    assertThat(answer.getNarrative().get(0).getRelatedData().getPackets()).isEmpty();
    assertThat(answer.getTimeline()).hasSize(1);
    assertThat(answer.getTimeline().get(0).getTitle()).isEqualTo("등록 요청 관측");
    assertThat(answer.getTimeline().get(0).getRelatedData().getPackets()).isEmpty();
    assertThat(answer.getSuggestedQuestions()).containsExactly("보호 방식은 무엇인가요?");
  }

  void generate(String custom) {
    when(llm.generateCompletion(anyString(), anyString()))
        .thenReturn(
            "{\"narrative\":[{\"title\":\"Summary\",\"content\":\"Synthetic\",\"type\":\"summary\"}],\"highlights\":[],\"timeline\":[],\"suggestedQuestions\":[]}");
    var answer = service.generateStory(fileId, "SUCI 분석", custom);
    var system = ArgumentCaptor.forClass(String.class);
    var prompt = ArgumentCaptor.forClass(String.class);
    verify(llm).generateCompletion(system.capture(), prompt.capture());
    assertProtocolFacts(prompt.getValue());
    assertThat(system.getValue()).contains(
        "UNTRUSTED DATA", "Never manufacture a SUCI", "Output language: Korean (ko-KR)",
        "JSON property names, enum values", "actual query");
    assertThat(answer.getPacketEvidence().decodedFrames()).isEqualTo(1);
    if (custom != null) assertThat(prompt.getValue()).contains(custom);
  }

  void assertProtocolFacts(String prompt) {
    assertThat(prompt)
        .contains(
            "nas_5gs.mm.suci.msin",
            "00000010",
            "5GS mobile identity",
            "e212.mcc",
            "00f1",
            "e212.mnc",
            "(01)",
            "nas_5gs.mm.suci.routing_indicator",
            "nas_5gs.mm.suci.scheme_id",
            "\"byteOffset\":92",
            "\"bitmask\":\"0xf\"",
            "\"packetNumber\":1",
            conversationId.toString(),
            "coverage");
  }
}
