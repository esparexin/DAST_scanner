import { z } from 'zod';
import type { IAIProvider, AIModelMessage, AICompletionOptions } from '../types.js';

const GeminiResponseSchema = z
  .object({
    candidates: z
      .array(
        z
          .object({
            content: z
              .object({
                parts: z
                  .array(
                    z
                      .object({
                        text: z.string().optional(),
                      })
                      .passthrough(),
                  )
                  .optional(),
              })
              .passthrough()
              .optional(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();

export class GeminiProvider implements IAIProvider {
  public readonly name = 'gemini';
  private readonly apiKey: string;
  public readonly model: string;

  constructor(apiKey?: string, model: string = 'gemini-1.5-flash') {
    this.apiKey = apiKey ?? process.env['GEMINI_API_KEY'] ?? '';
    this.model = model;
  }

  async generateCompletion(messages: AIModelMessage[], _options?: AICompletionOptions): Promise<string> {
    if (!this.apiKey) {
      throw new Error('Gemini API key is missing');
    }

    const contents = messages.map((m) => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents }),
    });

    if (!response.ok) {
      throw new Error(`Gemini request failed: HTTP ${response.status}`);
    }

    const rawData = await response.json();
    const parsed = GeminiResponseSchema.safeParse(rawData);
    if (!parsed.success) {
      throw new Error(`Gemini response validation failed: ${parsed.error.message}`);
    }

    return parsed.data.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
  }
}
