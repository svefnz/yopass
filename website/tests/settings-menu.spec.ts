import { test, expect } from '@playwright/test';
import { MockAPI } from './helpers/mock-api';

const COG = '[data-testid="settings-menu-button"]';
const MENU = '#settings-menu';

test.describe('Settings menu', () => {
  let mockAPI: MockAPI;

  test.beforeEach(async ({ page }) => {
    mockAPI = new MockAPI(page);
  });

  test.afterEach(async () => {
    await mockAPI.clearAllMocks();
  });

  async function open(page) {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.click(COG);
    await expect(page.locator(MENU)).toBeVisible();
  }

  test('cogwheel opens and closes the menu with correct aria state', async ({
    page,
  }) => {
    await mockAPI.mockConfigEndpoint();
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const cog = page.locator(COG);
    await expect(cog).toBeVisible();
    await expect(cog).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator(MENU)).not.toBeVisible();

    await cog.click();
    await expect(cog).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator(MENU)).toBeVisible();

    // Clicking outside (the app logo) closes the menu.
    await page.locator('header a[href="/"]').click();
    await expect(page.locator(MENU)).not.toBeVisible();
    await expect(cog).toHaveAttribute('aria-expanded', 'false');
  });

  test('contains language, theme, and date format settings', async ({
    page,
  }) => {
    await mockAPI.mockConfigEndpoint();
    await open(page);

    await expect(page.locator('#settings-language')).toBeVisible();
    await expect(page.locator('[data-testid="theme-toggle"]')).toBeVisible();
    await expect(
      page.locator('[data-testid="date-format-toggle"]'),
    ).toBeVisible();
  });

  test('changing the language updates the UI', async ({ page }) => {
    await mockAPI.mockConfigEndpoint();
    await open(page);

    await page.selectOption('#settings-language', 'sv');
    await expect(
      page.locator('h2:has-text("Kryptera meddelande")'),
    ).toBeVisible();
    // The menu stays open after the switch; the selector must reflect sv.
    await expect(page.locator('#settings-language')).toHaveValue('sv');

    // The choice is persisted.
    await page.reload();
    await page.waitForLoadState('networkidle');
    await expect(
      page.locator('h2:has-text("Kryptera meddelande")'),
    ).toBeVisible();
    await page.click(COG);
    await expect(page.locator('#settings-language')).toHaveValue('sv');
  });

  test('manual switch to Chinese persists and stays selected', async ({
    page,
  }) => {
    // Default English context: switch to Chinese by hand, then reload.
    await mockAPI.mockConfigEndpoint();
    await open(page);

    await page.selectOption('#settings-language', 'zh');
    await expect(page.locator('h2:has-text("加密消息")')).toBeVisible();
    await expect(page.locator('#settings-language')).toHaveValue('zh');

    await page.reload();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h2:has-text("加密消息")')).toBeVisible();
    await page.click(COG);
    await expect(page.locator('#settings-language')).toHaveValue('zh');
  });

  test('hides the language setting when NO_LANGUAGE_SWITCHER is set', async ({
    page,
  }) => {
    await mockAPI.mockConfigEndpoint({ NO_LANGUAGE_SWITCHER: true });
    await open(page);

    await expect(page.locator('#settings-language')).not.toBeVisible();
    // Theme and date format remain available.
    await expect(page.locator('[data-testid="theme-toggle"]')).toBeVisible();
    await expect(
      page.locator('[data-testid="date-format-toggle"]'),
    ).toBeVisible();
  });

  test('switches between light and dark themes', async ({ page }) => {
    await mockAPI.mockConfigEndpoint();
    await open(page);

    const html = page.locator('html');
    const themeToggle = page.locator('[data-testid="theme-toggle"]');
    const themeInput = themeToggle.locator('input');
    await expect(themeInput).not.toBeChecked();

    // The icons overlay the checkbox, so toggle by clicking the label.
    await themeToggle.click();
    await expect(themeInput).toBeChecked();
    await expect(html).toHaveAttribute('data-theme', 'dim');

    await themeToggle.click();
    await expect(html).toHaveAttribute('data-theme', 'emerald');
  });

  test('custom color override keeps the base theme background', async ({
    page,
  }) => {
    // Regression for #3687: a single custom override under a dark base theme
    // must not reset the background to light. The base theme stays applied and
    // only the overridden token changes.
    await mockAPI.mockConfigEndpoint({
      THEME_LIGHT: 'corporate',
      THEME_DARK: 'business',
      THEME_CUSTOM_DARK: { '--color-primary': 'oklch(65% 0.25 260)' },
    });
    await open(page);

    const html = page.locator('html');
    await page.locator('[data-testid="theme-toggle"]').click();
    await expect(html).toHaveAttribute('data-theme', 'business');

    // The business base theme defines a dark base-100 (background). If the
    // override had wiped the base theme it would fall back to white.
    const bg = await page.evaluate(() =>
      getComputedStyle(document.documentElement)
        .getPropertyValue('--color-base-100')
        .trim(),
    );
    expect(bg).not.toBe('');
    expect(bg).not.toMatch(/#fff|white|oklch\(1 0 0\)|rgb\(255, 255, 255\)/i);
  });

  test('date format toggle shows a live preview', async ({ page }) => {
    await mockAPI.mockConfigEndpoint();
    await open(page);

    const toggle = page.locator('[data-testid="date-format-toggle"]');
    const preview = page.locator('[data-testid="date-format-preview"]');
    const isoDate = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/;

    // ISO is on by default and the preview shows the ISO rendering.
    await expect(toggle).toBeChecked();
    await expect(preview).toHaveText(isoDate);

    // Turning ISO off switches the preview to the browser locale format.
    await toggle.uncheck();
    await expect(preview).not.toHaveText(isoDate);
  });

  test('handles config loading errors gracefully', async ({ page }) => {
    await page.route('**/config', async route => {
      await route.fulfill({
        status: 500,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': '*',
        },
        json: { message: 'Internal server error' },
      });
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // The settings menu still works with the default configuration.
    await page.click(COG);
    await expect(page.locator(MENU)).toBeVisible();
    await expect(page.locator('#settings-language')).toBeVisible();
  });

  test.describe('Language auto-detection from browser locale', () => {
    // Emulate a Chinese browser: navigator.language = "zh-CN". The page must
    // render Chinese AND the language selector must agree — regression: the
    // selector showed its first option (English) while the page was Chinese
    // because i18n.language stayed "zh-CN" and matched no <option>.
    test.use({ locale: 'zh-CN' });

    test('zh-CN browser gets Chinese UI with the selector agreeing', async ({
      page,
    }) => {
      await mockAPI.mockConfigEndpoint();
      await page.goto('/');
      await page.waitForLoadState('networkidle');

      await expect(page.locator('h2:has-text("加密消息")')).toBeVisible();

      await page.click(COG);
      await expect(page.locator('#settings-language')).toHaveValue('zh');
      await expect(
        page.locator('#settings-language option:checked'),
      ).toHaveText('中文');
    });
  });
});
