package com.tracepcap.story.service.narrator;

import com.tracepcap.common.stage.Tier;
import com.tracepcap.story.dto.NarrativeSection;

import com.tracepcap.story.spi.NarrationContext;
import com.tracepcap.story.spi.Narrator;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * States what this capture could <em>not</em> tell us, before anything is claimed about what it did.
 *
 * <p><b>Deterministic on purpose.</b> This is the section a language model should never write: it is
 * about the limits of the evidence, and a model asked to describe gaps will reach for plausible
 * prose rather than the actual gaps. Assembled from counts instead — no model, nothing to invent.
 *
 * <p>It also demonstrates what the {@link Narrator} seam is for. Before the registry, the story was
 * one LLM call, so every section had to come from a model because there was only one way in. This
 * one is {@link Tier#DETERMINISTIC} and sits alongside the LLM prose; the tier is now a property of
 * the section rather than an assumption about the whole story.
 *
 * <p>Contributes nothing when there is nothing to caveat — an empty section teaches readers to skim.
 */
@Component
public class CoverageNarrator implements Narrator {

  @Override
  public String name() {
    return "coverage";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  /** First: a reader should know the keyhole's shape before reading what was seen through it. */
  @Override
  public int order() {
    return 5;
  }

  @Override
  public List<NarrativeSection> narrate(NarrationContext context) {
    List<String> caveats = new ArrayList<>();

    // Null means nDPI did not complete — the share is unknowable, not zero and not 100% (#501).
    if (context.aggregates() != null && context.aggregates().getUnknownAppPct() == null) {
      caveats.add(
          "이 캡처에서는 애플리케이션 식별이 실행되지 않아 미식별 트래픽의 비율을 알 수 없습니다. "
              + "따라서 어떤 애플리케이션이 있었는지에 관한 분석은 불완전합니다. "
              + "이는 네트워크의 특성이 아니라 분석 도구의 실행 범위에 따른 한계입니다.");
    }

    if (context.summary() != null
        && (context.summary().startTime() == null || context.summary().endTime() == null)) {
      caveats.add(
          "캡처에 사용할 수 있는 타임스탬프가 없어 사건의 발생 시각이나 순서를 판단할 수 없습니다.");
    }

    if (caveats.isEmpty()) return List.of();

    return List.of(
        NarrativeSection.builder()
            .title("이 캡처로 확인할 수 없는 사항")
            .type(NarrativeSection.SectionType.summary)
            .content(
                "다음과 같은 분석 한계를 고려해 결과를 확인해 주세요:\n\n- "
                    + String.join("\n- ", caveats))
            .build());
  }
}
