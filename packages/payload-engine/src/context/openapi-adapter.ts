import type { ApplicableParameterType, TargetReflectionContext } from '../types/payload-definition.js';
import type { NormalizedApiEndpoint } from '@securityscan/api-parser';

export interface InferredParameterConstraint {
  name: string;
  inferredType: ApplicableParameterType;
  isEnum: boolean;
  enumValues?: string[];
  isNumeric: boolean;
  suggestedCategories: string[];
}

/**
 * Inspects OpenAPI/Swagger endpoint schemas to dynamically map parameter constraints
 * and skip irrelevant vulnerability checks.
 */
export class OpenApiParameterAdapter {
  static mapSchemaToConstraints(endpoint: NormalizedApiEndpoint, paramName: string): InferredParameterConstraint {
    const param = endpoint.parameters.find((p) => p.name === paramName);
    if (!param) {
      return {
        name: paramName,
        inferredType: 'string',
        isEnum: false,
        isNumeric: false,
        suggestedCategories: ['INJECTION', 'XSS', 'PATH_TRAVERSAL'],
      };
    }

    const rawType = (param.type || '').toLowerCase();
    let inferredType: ApplicableParameterType = 'string';
    let isNumeric = false;
    const suggestedCategories: string[] = [];

    if (rawType === 'integer' || rawType === 'int32' || rawType === 'int64') {
      inferredType = 'integer';
      isNumeric = true;
      suggestedCategories.push('INJECTION'); // SQLi arithmetic identities, boundary testing
    } else if (rawType === 'number' || rawType === 'float' || rawType === 'double') {
      inferredType = 'number';
      isNumeric = true;
      suggestedCategories.push('INJECTION');
    } else if (rawType === 'boolean') {
      inferredType = 'boolean';
    } else if (rawType === 'file' || rawType === 'binary') {
      inferredType = 'file';
      suggestedCategories.push('FILE_UPLOAD', 'PATH_TRAVERSAL');
    } else {
      // Check format hints
      if (paramName.toLowerCase().includes('id') && /^[0-9]+$/.test(paramName)) {
        inferredType = 'integer';
        isNumeric = true;
      } else if (paramName.toLowerCase().includes('uuid')) {
        inferredType = 'uuid';
      } else if (paramName.toLowerCase().includes('file') || paramName.toLowerCase().includes('path')) {
        inferredType = 'file';
        suggestedCategories.push('PATH_TRAVERSAL');
      } else {
        inferredType = 'string';
        suggestedCategories.push('INJECTION', 'XSS', 'PATH_TRAVERSAL');
      }
    }

    return {
      name: paramName,
      inferredType,
      isEnum: false,
      isNumeric,
      suggestedCategories,
    };
  }
}
