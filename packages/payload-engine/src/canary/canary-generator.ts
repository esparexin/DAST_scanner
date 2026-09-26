import { randomBytes } from 'node:crypto';

export type CanaryType = 'ALPHANUMERIC' | 'NUMERIC' | 'TAG_NAME' | 'UUID_LIKE' | 'RANDOM_TAG';

export interface GeneratedCanary {
  token: string;
  prefix: string;
  nonce: string;
  patternToObserve: string;
}

/**
 * Standardized, collision-resistant benign canary generator.
 * All canaries are harmless sentinels designed to prove syntax boundaries without exploit delivery.
 */
export class CanaryGenerator {
  static generate(
    prefix: string = 'canary',
    type: CanaryType = 'ALPHANUMERIC',
  ): GeneratedCanary {
    const nonce = randomBytes(4).toString('hex');
    let token: string;
    let pattern: string;

    switch (type) {
      case 'NUMERIC': {
        // Random 6-digit number to avoid target caching
        const numNonce = Math.floor(100000 + Math.random() * 900000).toString();
        token = numNonce;
        pattern = numNonce;
        break;
      }
      case 'RANDOM_TAG':
      case 'TAG_NAME': {
        token = `${prefix}${nonce}`;
        pattern = `<${token}>`;
        break;
      }
      case 'UUID_LIKE': {
        token = `00000000-0000-0000-0000-${nonce}0000`;
        pattern = token;
        break;
      }
      case 'ALPHANUMERIC':
      default: {
        token = `${prefix}${nonce}`;
        pattern = token;
        break;
      }
    }

    return {
      token,
      prefix,
      nonce,
      patternToObserve: pattern,
    };
  }
}
