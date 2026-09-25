import type { IAIProvider, AIModelMessage, AICompletionOptions } from '../types.js';

export class OpenAIProvider implements IAIProvider {
  public readonly name = 'openai';
  private readonly apiKey: string;
  private readonly model: string;
  private readonly baseUrl: string;

  constructor(apiKey?: string, model: string = 'gpt-4o-mini', baseUrl: string = 'https://api.openai.com/v1') {
    this.apiKey = apiKey ?? process.env['OPENAI_API_KEY'] ?? '';
    this.model = model;
    this.baseUrl = baseUrl;
  }

  async generateCompletion(messages: AIModelMessage[], options?: AICompletionOptions): Promise<string> {
    if (!this.apiKey) {
      throw new Error('OpenAI API key is missing');
    }

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        messages,
        temperature: options?.temperature ?? 0.1,
        max_tokens: options?.maxTokens ?? 1000,
        response_format: options?.jsonMode ? { type: 'json_object' } : undefined,
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI request failed: HTTP ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as any;
    return data.choices?.[0]?.message?.content ?? '';
  }
}
