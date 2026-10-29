---
paths:
  - "**/roles/*.tmdl"
---

# Row-level security rules

- Any change here is Tier 2. Explain the change and its effect on who sees which rows, then wait for approval
  (edits to `roles/` also trigger a permission prompt).
- Prefer dynamic RLS (`USERPRINCIPALNAME()` against a security table) over hardcoded user lists.
- Never put e-mail addresses or names of real people in role filters or descriptions.
- Filter dimension tables, not fact tables; check that relationships propagate the filter in one direction.
- Role membership is managed in the Service, not in TMDL; don't add members here.
- After a change, ask the user to test with "View as role" in Power BI Desktop; you cannot verify it here.
