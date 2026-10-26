# Security policy

Only the current default branch is maintained. For sensitive checker defects, use this repository's Security → Report a vulnerability option when available, or contact CompleteTech LLC through [complete.tech](https://complete.tech) to arrange private reporting. Include the commit, minimal synthetic reproduction, impact, and expected behavior. Do not include secrets or private target data. No response-time guarantee is made.

This tool assesses reported metadata; it does not verify reachable RCE or absence of a vulnerability. Direct service-specific findings to the owner's published disclosure process. Use only authorized inventories. Do not publish private assessment reports or vulnerability details belonging to third parties.

The checker does not invoke shells, application code, native decoders, network requests, or arbitrary inventory commands. Python itself should be run in a trusted environment. Metadata collection reflects only the current interpreter environment and does not attest all deployed workloads.
