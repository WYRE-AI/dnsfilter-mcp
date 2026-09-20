import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handlePolicyTool } from '../tools/policies.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handlePolicyTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('dnsfilter_list_policies forwards organization_id and include_global_policies', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [{ id: '1' }] }));

    await runWithCredentials(creds, () =>
      handlePolicyTool('dnsfilter_list_policies', { organization_id: 5, include_global_policies: true })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/policies');
    expect(url.searchParams.get('organization_id')).toBe('5');
    expect(url.searchParams.get('include_global_policies')).toBe('true');
  });

  it('dnsfilter_get_policy scopes the request to the policy ID in the path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { id: '3' } }));

    const result = await runWithCredentials(creds, () =>
      handlePolicyTool('dnsfilter_get_policy', { id: 3, include_relationships: false })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/policies/3');
    expect(url.searchParams.get('include_relationships')).toBe('false');
    expect(result.isError).toBeUndefined();
  });

  it('dnsfilter_get_application_policies requires application_id and organization_id, and array-encodes policy_ids', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: {} }));

    await runWithCredentials(creds, () =>
      handlePolicyTool('dnsfilter_get_application_policies', {
        application_id: 10,
        organization_id: 5,
        policy_ids: [1, 2],
      })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/policies/application');
    expect(url.searchParams.get('application_id')).toBe('10');
    expect(url.searchParams.get('organization_id')).toBe('5');
    expect(url.searchParams.getAll('policy_ids[]')).toEqual(['1', '2']);
  });

  it('dnsfilter_get_policy_permissive_mode hits the nested permissive_mode path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ permissive_mode: true }));

    const result = await runWithCredentials(creds, () =>
      handlePolicyTool('dnsfilter_get_policy_permissive_mode', { id: 8 })
    );

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/v1/policies/8/permissive_mode');
    expect(JSON.parse(textOf(result)).permissive_mode).toBe(true);
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handlePolicyTool('dnsfilter_list_policies', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DNSFILTER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
