`kronik privacy erase` would delete a row of the subject that another subject's row, or a row with no subject, still references. Deleting it would either fail the foreign-key check or, if the reference cascades or sets itself to null, change that other row. Nothing was written: the subject's keys are still there, and no `Erasure` record was appended.

Find the referencing row (the error names the actor and the tables), delete it or point it at a row that stays, and run the erasure again. A parent and a child that both belong to the subject are deleted together; this code is only the other subject's reference.

See also: `SUBJECT_ERASED`.
