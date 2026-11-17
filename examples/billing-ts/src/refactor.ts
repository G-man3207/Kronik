// billing-ts refactor: same domestic-VAT billing as src/actor.ts. Only
// structure differs so the component hash changes with no behavior change
// (dogfood scenario 1 in examples/payments-platform/).

import { billing } from "./billing.ts";
import { domesticVat } from "./vat.ts";

export default billing(domesticVat);