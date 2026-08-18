import { test, expect } from '@playwright/test';
import { MockAPI } from './helpers/mock-api';

// TOTP gate login continuation: the gate's login page stores the visitor's
// full URL (including the hash fragment, e.g. /#/s/{uuid}/{key}) in
// sessionStorage; after login the server only knows the server-visible path
// and redirects to it. The app reads the saved URL on boot and restores it.
test.describe('TOTP login continuation', () => {
  let mockAPI: MockAPI;

  test.beforeEach(async ({ page }) => {
    mockAPI = new MockAPI(page);
  });

  test.afterEach(async () => {
    await mockAPI.clearAllMocks();
  });

  test('restores the deep link saved by the login page', async ({ page }) => {
    await mockAPI.mockConfigEndpoint();
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Simulate what the TOTP login page script (remember.js) stored.
    await page.evaluate(() =>
      sessionStorage.setItem('yopass_totp_next', '/#/s/abcXYZ/pass123'),
    );

    await page.reload();
    await page.waitForURL('**/#/s/abcXYZ/pass123');

    // The saved URL is consumed exactly once.
    const leftover = await page.evaluate(() =>
      sessionStorage.getItem('yopass_totp_next'),
    );
    expect(leftover).toBeNull();
  });

  test('does nothing when no continuation is saved', async ({ page }) => {
    await mockAPI.mockConfigEndpoint();
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    expect(page.url()).not.toContain('#/');
    const leftover = await page.evaluate(() =>
      sessionStorage.getItem('yopass_totp_next'),
    );
    expect(leftover).toBeNull();
  });
});
