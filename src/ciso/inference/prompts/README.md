# Prompt templates and the model manifest

Prompt templates and the model manifest are version-controlled files that go through change
review like any other code (blueprint 8.3). Nothing in the platform writes them at run
time: `ciso.inference.manifest` can only read and verify.

- `manifest.json` lists every prompt template (`id`, `version`, `file`, `sha256`) and every
  model artifact (`id`, `version`, `sha256`, `source`).
- A template file is never edited in place once released. A change is a new file and a new
  `version` entry; the old entry stays so old invocation records still resolve.
- The sha256 is taken over the file bytes after converting CRLF to LF, so the pin does not
  depend on how a checkout handles line endings.
- Loading refuses (`IntegrityFailure`) on a hash mismatch, a missing file, a duplicate
  `id` plus `version`, a path that leaves this directory, or any key the loader does not
  know.
- Placeholders in a template are written `{{name}}`. A request must supply exactly the
  placeholders the template contains.
- The stub model is listed in the manifest like any other model artifact. Its `sha256`
  is the hash of the stub's fixed descriptor (`ciso.inference.stub.STUB_DESCRIPTOR`).

To change a template: add the new file, compute its sha256 (LF line endings), add the
manifest entry, and submit both for review.
