import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useOutletContext } from 'react-router-dom';
import type { Story } from '@/types';
import type { StoryGenerationState } from '@/pages/Analysis/AnalysisPage';
import { StoryPage } from '../StoryPage';

vi.mock('react-router-dom', () => ({ useOutletContext: vi.fn() }));
vi.mock('@/features/timeline/services/timelineService', () => ({
  timelineService: { getTimelineData: vi.fn().mockResolvedValue([]) },
}));
vi.mock('@/features/story/services/storyService', () => ({
  storyService: { getInvestigation: vi.fn().mockResolvedValue({ answers: [], unknowns: [] }) },
}));
vi.mock('@components/story/NarrativeView', () => ({
  NarrativeView: () => <p>Stored narrative</p>,
}));
vi.mock('@components/story/StoryTimeline', () => ({ StoryTimeline: () => null }));
vi.mock('@components/story/StorySectionNav/StorySectionNav', () => ({
  StorySectionNav: ({ sections }: { sections: { id: string; label: string }[] }) => (
    <nav aria-label="Story sections">
      {sections.map(section => (
        <span key={section.id}>{section.label}</span>
      ))}
    </nav>
  ),
}));
vi.mock('@components/story/StoryProgress/StoryProgress', () => ({
  StoryProgress: () => <p>Generating story</p>,
}));
vi.mock('@components/story/ConfirmedFindingsPanel/ConfirmedFindingsPanel', () => ({
  ConfirmedFindingsPanel: () => null,
}));
vi.mock('@components/story/StoryInfoCard', () => ({ StoryInfoCard: () => null }));
vi.mock('@components/story/StoryChat', () => ({ StoryChat: () => null }));
vi.mock('@components/story/AggregatesPanel', () => ({ AggregatesPanel: () => null }));
vi.mock('@components/story/FindingsPanel', () => ({ FindingsPanel: () => null }));
vi.mock('@components/story/InvestigationPanel', () => ({ InvestigationPanel: () => null }));
vi.mock('@components/timeline/TrafficTimeline', () => ({ TrafficTimeline: () => null }));

const storedStory: Story = {
  id: 'stored-story',
  fileId: 'capture',
  generatedAt: 1,
  narrative: [],
  highlights: [],
  timeline: [],
};

function state(overrides: Partial<StoryGenerationState> = {}): StoryGenerationState {
  return {
    story: null,
    setStory: vi.fn(),
    generating: false,
    generateStory: vi.fn().mockResolvedValue(undefined),
    error: null,
    setError: vi.fn(),
    contextError: null,
    setContextError: vi.fn(),
    editablePrompt: '',
    setEditablePrompt: vi.fn(),
    elapsedSeconds: 0,
    llmTimeoutMs: 300000,
    additionalContext: '',
    setAdditionalContext: vi.fn(),
    maxFindings: 20,
    setMaxFindings: vi.fn(),
    maxRiskMatrix: 15,
    setMaxRiskMatrix: vi.fn(),
    totalFindings: undefined,
    setTotalFindings: vi.fn(),
    totalRiskMatrix: undefined,
    setTotalRiskMatrix: vi.fn(),
    ...overrides,
  };
}

function setContext(storyState: StoryGenerationState) {
  vi.mocked(useOutletContext).mockReturnValue({ fileId: 'capture', storyState });
}

describe('StoryPage asynchronous story transitions', () => {
  it.each([
    { initial: {}, label: 'empty' },
    { initial: { generating: true }, label: 'generating' },
    { initial: { error: 'Previous generation failed' }, label: 'failed' },
    {
      initial: { contextError: { promptText: 'prompt', promptTokens: 2000, contextLength: 1000 } },
      label: 'context error',
    },
  ])(
    'renders a story arriving after the $label state without changing hook order',
    async ({ initial }) => {
      setContext(state(initial));
      const { rerender } = render(<StoryPage />);

      setContext(state({ story: storedStory }));
      expect(() => rerender(<StoryPage />)).not.toThrow();
      expect(await screen.findByRole('heading', { name: 'Network Traffic Story' })).toBeVisible();
      expect(screen.getByText('Stored narrative')).toBeVisible();
      expect(screen.getByRole('navigation', { name: 'Story sections' })).toHaveTextContent(
        'Narrative'
      );

      setContext(state());
      expect(() => rerender(<StoryPage />)).not.toThrow();
      expect(screen.getByText('No Story Generated Yet')).toBeVisible();
    }
  );
});
