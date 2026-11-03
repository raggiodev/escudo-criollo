import { StoreAuditReport, safeTruncate } from '../types';

export const MAX_X_ALERT_TWEET_CHARS = 230;
const TWEET_FOOTER = 'Detectado con 🛡️ Escudo Criollo';

/**
 * Generates a concise, reputation-safe X/Twitter fraud alert strictly <= 230 characters.
 * Intended ONLY for DANGER (confirmed concrete fraud signals) reports.
 */
export function buildSafeXAlertTweet(report: StoreAuditReport): {
  tweetText: string;
  intentUrl: string;
} {
  const host = safeTruncate(report.hostname, 44);
  const dangerFindings = report.findings.filter((f) => f.severity === 'DANGER');
  const primaryReason = dangerFindings[0]
    ? safeTruncate(dangerFindings[0].title, 76)
    : 'Señales críticas de fraude fiscal en tienda online';

  const headerLine = `🚨 Alerta tienda sospechosa: ${host} (${report.trustScore}/100)`;
  const reasonLine = `• ${primaryReason}`;
  const cautionLine = 'Verificá CUIT antes de transferir.';

  let tweetText = `${headerLine}\n${reasonLine}\n${cautionLine}\n${TWEET_FOOTER}`;

  if (tweetText.length > MAX_X_ALERT_TWEET_CHARS) {
    tweetText = `${headerLine}\n${reasonLine}\n${TWEET_FOOTER}`;
  }

  if (tweetText.length > MAX_X_ALERT_TWEET_CHARS) {
    const budget = Math.max(
      12,
      MAX_X_ALERT_TWEET_CHARS - headerLine.length - TWEET_FOOTER.length - 5,
    );
    tweetText = `${headerLine}\n• ${safeTruncate(primaryReason, budget)}\n${TWEET_FOOTER}`;
  }

  tweetText = tweetText.slice(0, MAX_X_ALERT_TWEET_CHARS);

  const intent = new URL('https://x.com/intent/tweet');
  intent.searchParams.set('text', tweetText);

  return {
    tweetText,
    intentUrl: intent.toString(),
  };
}

