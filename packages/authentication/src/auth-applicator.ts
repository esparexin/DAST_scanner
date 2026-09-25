import { AuthType } from '@securityscan/contracts';
import type { IAuthConfiguration } from '@securityscan/contracts';

/**
 * Applies authentication credentials to outbound HTTP requests.
 * Never logs or exposes the actual credential values.
 */
export class AuthApplicator {
  apply(
    type: AuthType,
    config: IAuthConfiguration,
    headers: Record<string, string>,
  ): Record<string, string> {
    const result = { ...headers };

    switch (type) {
      case AuthType.BEARER_TOKEN:
      case AuthType.JWT:
        if (config.token) {
          result['Authorization'] = `Bearer ${config.token}`;
        }
        break;

      case AuthType.API_KEY:
        if (config.apiKeyHeader && config.apiKeyValue) {
          result[config.apiKeyHeader] = config.apiKeyValue;
        }
        break;

      case AuthType.COOKIE_SESSION:
        if (config.cookies) {
          result['Cookie'] = Object.entries(config.cookies)
            .map(([k, v]) => `${k}=${v}`)
            .join('; ');
        }
        break;

      case AuthType.CUSTOM_HEADER:
        if (config.customHeaders) {
          Object.assign(result, config.customHeaders);
        }
        break;

      case AuthType.NONE:
      default:
        break;
    }

    return result;
  }

  getAuthLabel(type: AuthType, config: IAuthConfiguration): string {
    switch (type) {
      case AuthType.BEARER_TOKEN:
      case AuthType.JWT:
        return 'bearer';
      case AuthType.API_KEY:
        return `api-key:${config.apiKeyHeader ?? 'unknown'}`;
      case AuthType.COOKIE_SESSION:
        return 'cookie';
      case AuthType.CUSTOM_HEADER:
        return 'custom';
      case AuthType.OAUTH2:
      case AuthType.OIDC:
        return 'oauth';
      case AuthType.NONE:
      default:
        return 'anonymous';
    }
  }
}
