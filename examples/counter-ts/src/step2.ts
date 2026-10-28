// counter-ts-step2: increments by 2, a changed behavior for the M3 tests
// (see counter.ts). Built with `kronik build --entry src/step2.ts`.

import { counter } from "./counter.ts";

export default counter(2);
