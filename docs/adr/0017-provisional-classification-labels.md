# ADR-0017: Provisional classification labels (no built-in scheme; `unknown` outranks every label)
Status: Proposed (reversible default; owner approval pending)
Date: 2026-11-17
Revised: 2026-11-18 (identity no longer needs a scheme)
Blueprint refs: §4.5, §8.1 (usage governance), §8.4, §11.1, §18 Phase 0 exit gate (initial data classification), FR-031, NFR-007, OD-09, OD-14, Appendix C; plan gap G7

## Context
The company's data classes are an open decision (OD-09, Phase 0 with business/legal). BP §11.1 requires data to be classified before it is placed in a prompt, retrieved context, evidence artifact or external request, and says: "If classification is unknown, treat as sensitive until classified." An earlier design fixed a set of labels in code. That would have decided OD-09 silently (plan gap G7), so the labels were moved to configuration.

## Options considered

| Option | Gains | Costs | Security impact |
|---|---|---|---|
| No scheme in code; `ClassificationScheme` takes ordered labels from settings; `unknown` is built in and outranks every configured label | OD-09 stays open; the company's own labels can be loaded without a code change; unclassified data is always handled as the most sensitive | A single ordered list cannot express categories that are not ordered against each other (for example personal data and customer content); changing labels later affects stored records | Fail-safe default. A label nobody configured is refused, not guessed. `unknown` can never pass a ceiling |
| A fixed set of labels in code | Simplest; type-checked | Decides OD-09 without the company; changing it is a code change | The platform's labels could diverge from the company's policy without anyone noticing |
| No classification until OD-09 is answered; treat everything as `unknown` | Decides nothing | Paths that depend on a ceiling (evidence access, minimization, external inference allow-list) cannot be exercised with realistic data | Safest. This is the intended state when no settings file is named |
| Several dimensions: a sensitivity level plus category tags | Can express OD-09's full list (data classes, customer data categories, secrets, personal data, transfer restrictions) | More design than the evidence supports today | Finer control later; premature now |

## Default chosen for the local build
`ciso.common.classification.ClassificationScheme` holds an ordered tuple of labels, least sensitive first. No label name appears in `src`.
- `Settings.classification_labels` defaults to unset. With no settings file there is no scheme. `IdentityService` takes the scheme as optional: with none, an assignment that narrows by classification is refused and everything else works, so the platform starts and the identity and kill-switch paths run. Anything that needs a ceiling, such as external inference and evidence access, refuses until a scheme is configured.
- `unknown` is built in. It cannot be configured as a label, it ranks above every configured label, it never passes a configured ceiling and it cannot be used as a ceiling.
- A missing or empty label is normalised to `unknown`. A label that is not in the configured list is refused.
- For a mixed set of labels the most sensitive one governs. An empty set is `unknown`.
- External inference may name allowed classifications only if a scheme is set and every name is in it.

`config/provisional-settings.json` sets:

```
"classification_labels": ["public", "internal", "confidential", "restricted"]
```

These four labels are placeholders. They are not the company's classification scheme, they were not agreed with anyone, and they exist only so that classification-dependent paths can be exercised locally.

Weaknesses of this default:
- A provisional file in the repository can be mistaken for a decision. The file's own comment says it is provisional; that is the only guard.
- Stored records carry label strings. Renaming or removing a label later needs a mapping for existing records, because an unrecognised label is refused.
- The order is total. If the company's classes are not a single ladder, this model does not fit and must change.
- Who assigns a label to an item, and on what basis, is not decided here. A wrong label lower than the truth is not detected by the scheme.

## Why this default is reversible
Seam: `ClassificationScheme`, built from `Settings.classification_labels`. Modules ask the scheme to normalise, rank and compare; they do not know the label names. To adopt the company's scheme: put its labels, in order, in the settings file and map any records stored under the placeholders. To move to several dimensions: extend the scheme class and the records that carry a label; callers that only ask "is this at most X" keep working.

## Evidence needed to make this final
- The company's classification policy, or leadership's decision on an initial scheme (Phase 0 checklist DAT-01).
- Customer data categories and where personal data is held (DAT-02, DAT-04).
- Transfer and storage restrictions that attach to specific classes (DAT-05).
- Which classes may be placed in a local prompt and which may never go to an external provider (DAT-07, OD-14).
- Who classifies data at each source, from the source-system matrix (data sensitivity column).

## Consequences
- The Phase 0 gate item "initial data classification" is answered by people. The settings file is then updated to match.
- Until then, anything classified under the placeholders should be treated as unclassified when the real scheme arrives.
- Tests should set the labels they need and should not read the provisional file, so that a change to the placeholders cannot change a test result.
