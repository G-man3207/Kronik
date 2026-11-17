// billing-ts reorder: adds GET {payments}/healthz after charge (inserted call).
// Dogfood scenario 3 in examples/payments-platform/ — inserted outbound call.

import { billing } from "./billing.ts";
import { domesticVat } from "./vat.ts";

export default billing(domesticVat, { pingPaymentsAfterCharge: true });