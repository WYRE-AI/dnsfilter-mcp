import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleBlockPageTool } from '../tools/block-pages.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleBlockPageTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('dnsfilter_list_block_pages forwards organization_id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ name: 'Default' }]));

    const result = await runWithCredentials(creds, () =>
      handleBlockPageTool('dnsfilter_list_block_pages', { organization_id: 12 })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/block_pages');
    expect(url.searchParams.get('organization_id')).toBe('12');
    expect(result.isError).toBeUndefined();
  });

  it('dnsfilter_get_block_page scopes the request to the block page ID in the path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ name: 'Default', organization_id: 12 }));

    const result = await runWithCredentials(creds, () =>
      handleBlockPageTool('dnsfilter_get_block_page', { id: 2 })
    );

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/v1/block_pages/2');
    expect(JSON.parse(textOf(result)).name).toBe('Default');
  });

  it('surfaces a 429 as a readable rate-limit error', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'rate limited' }, 429));

    const result = await runWithCredentials(creds, () =>
      handleBlockPageTool('dnsfilter_list_block_pages', {})
    );

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/rate-limited/i);
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handleBlockPageTool('dnsfilter_list_block_pages', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DNSFILTER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
