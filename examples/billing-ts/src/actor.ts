// billing as deployed: the seller's domestic VAT on every invoice (see
// billing.ts and vat.ts).

import { billing } from "./billing.ts";
import { domesticVat } from "./vat.ts";

export default billing(domesticVat);
