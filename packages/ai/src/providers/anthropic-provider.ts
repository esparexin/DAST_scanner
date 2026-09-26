import { z } from 'zod';
import type { IAIProvider, AIModelMessage, AICompletionOptions } from '../types.js';

const AnthropicResponseSchema = z
  .object({
    content: z
      .array(
        z
          .object({
            type: z.string().optional(),
            text: z.string().optional(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();

export class AnthropicProvider implements IAIProvider {
  public readonly name = 'anthropic';
  private readonly apiKey: string;
  public readonly model: string;

  constructor(apiKey?: string, model: string = 'claude-3-5-sonnet-20241022') {
    this.apiKey = apiKey ?? process.env['ANTHROPIC_API_KEY'] ?? '';
    this.model = model;
  }

  async generateCompletion(messages: AIModelMessage[], options?: AICompletionOptions): Promise<string> {
    if (!this.apiKey) {
      throw new Error('Anthropic API key is missing');
    }

    const system = messages.find((m) => m.role === 'system')?.content ?? '';
    const userMsgs = messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({ role: m.role, content: m.content }));

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        system,
        messages: userMsgs,
        max_tokens: options?.maxTokens ?? 1000,
        temperature: options?.temperature ?? 0.1,
      }),
    });

    if (!response.ok) {
      throw new Error(`Anthropic request failed: HTTP ${response.status}`);
    }

    const rawData = await response.json();
    const parsed = AnthropicResponseSchema.safeParse(rawData);
    if (!parsed.success) {
      throw new Error(`Anthropic response validation failed: ${parsed.error.message}`);
    }

    return parsed.data.content?.[0]?.text ?? '';
  }
}
