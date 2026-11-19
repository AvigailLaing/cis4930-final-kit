# Rotating a scored account without breaking the check

The scoring engine does not just test whether a port is open. For some services it logs in with a real
account. Those accounts are editable, per service, from the team view of the scoring engine.

## Where the credentials live

1. Open the scoring engine and click **SERVICES**.
2. Click the service in the left list, e.g. `PD-SSH` or `DC-LDAP`.
3. The page shows an **ACCOUNTS** panel: `Username` and `Password`, with an eye icon that reveals the
   current value.
4. Under it, a **CHECKS** table with one row per check: ROUND, RESULT, EARNED, REASON, TIMESTAMP.
   Checks run roughly every 3 minutes, so a mistake is visible within one cycle.

Observed on the mock: `PD-SSH` uses `ftruman`. `DC-LDAP` uses a domain account. Check both.

## The procedure, in this order

```
1. screenshot the ACCOUNTS panel BEFORE you touch anything
   (that value is your restore point, and your before/after evidence)

2. rotate the account on the box
   sudo passwd ftruman                 # or bash blue.sh rotate --apply

3. back on the scoring engine: SERVICES -> that service -> ACCOUNTS
   type the new password into the Password field, save

4. wait for the next check (about 3 minutes), watch the CHECKS table
   you want: RESULT = UP, EARNED = 100, REASON = Check Finished Successfully

5. screenshot the panel and the green check together
```

If the check goes red after step 4, the password did not save, or you rotated a different account than
the one named in the ACCOUNTS panel. Fix it by typing the new value again, not by reverting the rotation.

## If you would rather not touch it

Leave that one account's password alone, rotate everything else, and say so in the report:

"Why we did not rotate the check account: the scoring engine authenticates as ftruman to test SSH, and
the report is worth more than the risk of a red check. We rotated every other account, including the
service accounts, and verified the checks stayed green."

That is a complete, defensible answer. Both routes earn the same report marks.
