import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { storyService } from '@/features/story/services/storyService';
import { StoryChat } from '../StoryChat';

afterEach(() => vi.restoreAllMocks());

function ask(question: string) {
  const input = screen.getByRole('textbox');
  fireEvent.change(input, { target: { value: question } });
  fireEvent.keyDown(input, { key: 'Enter' });
}

describe('StoryChat packet evidence', () => {
  it('shows partial evidence honestly and keeps metadata out of subsequent chat history', async () => {
    const request = vi.spyOn(storyService, 'askQuestion').mockResolvedValue({
      answer: 'SUCI is present in frame 1.',
      followUpQuestions: [],
      modelUsed: 'gpt-6-astra',
      packetEvidence: {
        status: 'partial',
        selection: 'NAS fields matching the question',
        totalFrames: 100,
        searchFrameLimit: 90,
        matchedFrames: 8,
        selectedFrames: 2,
        decodedFrames: 2,
        includedFields: 40,
        omittedFields: 5,
        unsearchedFrames: 10,
        warnings: ['Only selected packets were included.'],
      },
    });
    render(<StoryChat storyId="story" />);
    ask('Is there a SUCI?');
    await screen.findByText('SUCI is present in frame 1.');
    expect(screen.getByText('Model: gpt-6-astra')).toBeVisible();
    fireEvent.click(screen.getByText('Packet evidence · Partial coverage'));
    expect(screen.getByText('2 decoded frames · 40 fields')).toBeVisible();
    expect(screen.getByText('10 frames outside the search range')).toBeVisible();
    expect(screen.getByText('5 fields omitted')).toBeVisible();
    expect(screen.getByText('Only selected packets were included.')).toBeVisible();

    ask('Which protection scheme?');
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request.mock.calls[1]).toEqual([
      'story',
      'Which protection scheme?',
      [
        { role: 'user', text: 'Is there a SUCI?' },
        { role: 'assistant', text: 'SUCI is present in frame 1.' },
      ],
    ]);
  });

  it('still displays answers from servers without evidence metadata', async () => {
    vi.spyOn(storyService, 'askQuestion').mockResolvedValue({
      answer: 'The stored story is available.',
      followUpQuestions: [],
    });
    render(<StoryChat storyId="old-story" />);
    ask('What was observed?');
    expect(await screen.findByText('The stored story is available.')).toBeVisible();
    expect(screen.queryByLabelText('Packet evidence coverage')).not.toBeInTheDocument();
  });
});
