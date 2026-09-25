import { describe, it, expect } from 'vitest';
import { ApiParserCoordinator } from '../coordinator.js';
import { ApiSchemaFormat, ApiType } from '@securityscan/contracts';

describe('ApiParserCoordinator', () => {
  const coordinator = new ApiParserCoordinator();

  it('routes and parses OpenAPI JSON specs', () => {
    const openApi = JSON.stringify({
      openapi: '3.0.0',
      info: { title: 'Order Service', version: '2.0.0' },
      paths: {
        '/orders': {
          get: {
            operationId: 'listOrders',
            responses: { '200': { description: 'OK' } },
          },
        },
      },
    });

    const result = coordinator.parse(openApi, ApiSchemaFormat.OPENAPI_JSON);
    expect(result.valid).toBe(true);
    expect(result.type).toBe(ApiType.REST);
    expect(result.title).toBe('Order Service');
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0]?.path).toBe('/orders');
  });

  it('routes and parses GraphQL introspection JSON', () => {
    const gql = JSON.stringify({
      data: {
        __schema: {
          queryType: { name: 'Query' },
          types: [
            {
              name: 'Query',
              fields: [{ name: 'getUser', type: { name: 'User' }, args: [{ name: 'id', type: 'ID!' }] }],
            },
          ],
        },
      },
    });

    const result = coordinator.parse(gql, ApiSchemaFormat.GRAPHQL_INTROSPECTION);
    expect(result.valid).toBe(true);
    expect(result.type).toBe(ApiType.GRAPHQL);
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0]?.operationId).toBe('getUser');
  });

  it('routes and parses WSDL contracts', () => {
    const wsdl = `<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:operation name="TransferFunds"/>
</wsdl:definitions>`;

    const result = coordinator.parse(wsdl, ApiSchemaFormat.WSDL);
    expect(result.valid).toBe(true);
    expect(result.type).toBe(ApiType.SOAP);
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0]?.operationId).toBe('TransferFunds');
  });
});
