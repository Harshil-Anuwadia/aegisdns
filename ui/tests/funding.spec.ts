import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';

test('funding page uses the verified sponsor destination without automatic outbound requests', async ({ page }) => {
  const external: string[] = [];
  page.on('request', request => { if (new URL(request.url()).origin !== 'http://127.0.0.1:4173') external.push(request.url()); });
  const writes = await mockApi(page);
  await page.goto('/#overview');
  await page.getByRole('link', { name: 'Support AegisDNS', exact: true }).click();
  await expect(page).toHaveURL(/#support$/);
  const sponsor = page.getByRole('link', { name: 'Sponsor on GitHub' });
  await expect(sponsor).toHaveAttribute('href', 'https://github.com/sponsors/Harshil-Anuwadia');
  await expect(sponsor).toHaveAttribute('rel', 'noopener noreferrer');
  await expect(page.getByText('The same software for everyone.')).toBeVisible();
  expect(external).toEqual([]);
  expect(writes).toEqual([]);
});

test('business inquiry is previewed locally, downloadable and invalidated when edited', async ({ page }) => {
  const writes = await mockApi(page); await page.goto('/#support');
  await page.getByLabel('Interested in').selectOption('engineering');
  await page.getByLabel('Organization', { exact: true }).fill('Example & Sons');
  await page.getByLabel('What would you like to accomplish?').fill('Package a reproducible Linux deployment with acceptance tests.');
  await page.getByLabel('Preferred timing (optional)').fill('Next quarter');
  await page.getByRole('button', { name: 'Prepare inquiry' }).click();
  const link = page.getByRole('link', { name: 'Review draft on GitHub' });
  const url = new URL((await link.getAttribute('href'))!);
  expect(url.origin + url.pathname).toBe('https://github.com/Harshil-Anuwadia/aegisdns/issues/new');
  expect(url.searchParams.get('body')).toContain('Example & Sons');
  expect(url.searchParams.get('body')).toContain('Fund a public improvement');
  expect(url.searchParams.get('body')).not.toContain('192.168.');
  await expect(page.getByLabel('Draft text')).toHaveValue(url.searchParams.get('body')!);
  expect(writes).toEqual([]);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download draft' }).click();
  expect((await download).suggestedFilename()).toBe('aegisdns-partnership.md');
  await page.getByLabel('Organization', { exact: true }).fill('Revised organization');
  await expect(page.getByRole('link', { name: 'Review draft on GitHub' })).toHaveCount(0);
  expect(writes).toEqual([]);
});
