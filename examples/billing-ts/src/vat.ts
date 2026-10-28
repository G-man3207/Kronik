// VAT for billing-ts's invoices. The seller is in Sweden. The rates are the
// EU standard rates, in basis points (2550 = 25.5 %), for illustration; this
// is an example, not tax advice.

export const SELLER_COUNTRY = "SE";

export const EU_RATES: Record<string, number> = {
  AT: 2000, BE: 2100, BG: 2000, CY: 1900, CZ: 2100, DE: 1900, DK: 2500,
  EE: 2400, ES: 2100, FI: 2550, FR: 2000, GR: 2400, HR: 2500, HU: 2700,
  IE: 2300, IT: 2200, LT: 2100, LU: 1700, LV: 2100, MT: 1800, NL: 2100,
  PL: 2300, PT: 2300, RO: 2100, SE: 2500, SI: 2200, SK: 2300,
};

/** Who the invoice is for, as far as VAT is concerned. */
export interface VatCustomer {
  /** ISO 3166-1 alpha-2, such as "DE". */
  country: string;
  /** The customer's VAT number, if it is a business that has one. */
  vat_id: string | null;
}

/** The rate an invoice gets, and why. */
export interface Vat {
  rate_bp: number;
  rule: string;
}

/** How an invoice's VAT is chosen. */
export type VatRule = (customer: VatCustomer) => Vat;

/** The seller's domestic rate on every invoice, wherever the customer is. */
export const domesticVat: VatRule = () => ({ rate_bp: EU_RATES[SELLER_COUNTRY], rule: `domestic ${SELLER_COUNTRY}` });

/**
 * "Apply EU VAT": domestic rate at home; reverse charge (0 %) for businesses
 * with a VAT number elsewhere in the EU; the customer's country's rate for
 * other EU customers (one-stop shop); none outside the EU (export).
 */
export const euVat: VatRule = (customer) => {
  const rate = EU_RATES[customer.country];
  if (customer.country === SELLER_COUNTRY) return { rate_bp: rate, rule: `domestic ${SELLER_COUNTRY}` };
  if (rate === undefined) return { rate_bp: 0, rule: "export" };
  if (customer.vat_id !== null) return { rate_bp: 0, rule: "reverse charge" };
  return { rate_bp: rate, rule: `OSS ${customer.country}` };
};

/** VAT on `net` minor units at `rate_bp`, rounded half up to a minor unit. */
export function vatOf(net: number, rate_bp: number): number {
  return Math.floor((net * rate_bp + 5000) / 10000);
}
