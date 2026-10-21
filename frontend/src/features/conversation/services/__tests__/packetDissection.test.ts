import { HttpResponse, http } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { conversationService } from '../conversationService';

describe('conversationService.getPacketDissection', () => {
  it('uses the original frame number in the conversation-scoped endpoint', async () => {
    server.use(
      http.get('*/api/v1/conversations/detail/session-1/packets/142/dissection', () =>
        HttpResponse.json({
          packetNumber: 142,
          capturedLength: 4,
          originalLength: 4,
          rawHex: '7e004101',
          decoder: 'TShark',
          protocols: [],
          warnings: [],
          nasDetected: true,
        })
      )
    );
    const result = await conversationService.getPacketDissection('session-1', 142);
    expect(result.packetNumber).toBe(142);
    expect(result.rawHex).toBe('7e004101');
  });
});
