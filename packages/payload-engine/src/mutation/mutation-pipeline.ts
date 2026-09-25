import type { IPayloadDefinition, TransformationType } from '../types/payload-definition.js';
import { CanaryGenerator } from '../canary/canary-generator.js';

export interface MaterializedTestVariant {
  payloadId: string;
  transformation: TransformationType;
  canaryToken?: string;
  finalValue: string;
  description: string;
  isHppVariant?: boolean;
  hppKey?: string;
}

export class MutationPipeline {
  /**
   * Materialize an abstract payload template into concrete, transformed test variants
   */
  materialize(
    payload: IPayloadDefinition,
    targetParamName: string,
    baselineValue: string = '',
    requestedTransformations?: TransformationType[],
  ): MaterializedTestVariant[] {
    const variants: MaterializedTestVariant[] = [];

    // Generate benign canary token if template requires it
    let canaryToken: string | undefined;
    if (payload.template.raw.includes('{{CANARY}}')) {
      const prefix = payload.template.canaryPrefix ?? 'canary';
      const gen = CanaryGenerator.generate(prefix, payload.template.defaultCanaryType ?? 'ALPHANUMERIC');
      canaryToken = gen.token;
    }

    // Base resolution of placeholders
    let resolvedRaw = payload.template.raw
      .replace(/{{PARAM}}/g, targetParamName)
      .replace(/{{VALUE}}/g, baselineValue);

    if (canaryToken) {
      resolvedRaw = resolvedRaw.replace(/{{CANARY}}/g, canaryToken);
    }

    const allowedTransforms = payload.template.supportedTransformations;
    const toApply = requestedTransformations
      ? requestedTransformations.filter((t) => allowedTransforms.includes(t))
      : allowedTransforms.slice(0, 4);

    // Always include raw (NONE)
    variants.push({
      payloadId: payload.id,
      transformation: 'NONE',
      canaryToken,
      finalValue: resolvedRaw,
      description: `${payload.name} (Raw)`,
    });

    for (const transform of toApply) {
      if (transform === 'NONE') continue;

      if (transform === 'HPP_POLLUTION') {
        // HTTP Parameter Pollution: generate array bracket and duplicate parameter
        variants.push({
          payloadId: payload.id,
          transformation: 'HPP_POLLUTION',
          canaryToken,
          finalValue: resolvedRaw,
          description: `${payload.name} (HPP Duplicate Key)`,
          isHppVariant: true,
          hppKey: targetParamName,
        });
        variants.push({
          payloadId: payload.id,
          transformation: 'HPP_POLLUTION',
          canaryToken,
          finalValue: resolvedRaw,
          description: `${payload.name} (HPP Array Notation)`,
          isHppVariant: true,
          hppKey: `${targetParamName}[]`,
        });
        continue;
      }

      const transformedValue = this.applyTransformation(resolvedRaw, transform);
      variants.push({
        payloadId: payload.id,
        transformation: transform,
        canaryToken,
        finalValue: transformedValue,
        description: `${payload.name} (${transform})`,
      });
    }

    return variants;
  }

  private applyTransformation(val: string, type: TransformationType): string {
    switch (type) {
      case 'URL_ENCODE':
        return encodeURIComponent(val);

      case 'DOUBLE_URL_ENCODE':
        return encodeURIComponent(encodeURIComponent(val));

      case 'HTML_ENTITY':
        return val
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;');

      case 'JSON_ESCAPE':
        return JSON.stringify(val).slice(1, -1); // Trim outer quotes

      case 'WHITESPACE_ALTERNATIVE':
        return val.replace(/ /g, '/**/');

      case 'CASE_VARIATION':
        return val
          .split('')
          .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()))
          .join('');

      case 'NULL_BYTE_PREFIX':
        return `%00${val}`;

      case 'NONE':
      default:
        return val;
    }
  }
}
