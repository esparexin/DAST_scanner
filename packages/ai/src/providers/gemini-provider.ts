import type { IAIProvider, AIModelMessage, AICompletionOptions } from '../types.js';

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

    const data = (await response.json()) as any;
    return data.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
  }
}
