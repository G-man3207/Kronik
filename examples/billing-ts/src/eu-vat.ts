// "Apply EU VAT to invoices": billing with the EU rules instead of the
// domestic rate, which changes the charged amount for customers outside
// Sweden. Built with `kronik build --entry src/eu-vat.ts`
// (dist/billing-eu-vat.wasm) and proposed with `kronik propose`; the change
// to `POST payments.internal/v1/charges` needs approval under the default
// rule payments-must-be-exact.

import { billing } from "./billing.ts";
import { euVat } from "./vat.ts";

export default billing(euVat);
