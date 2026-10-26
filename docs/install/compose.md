# Evaluate with Docker Compose

One command brings up the platform with sign-in, write-once evidence storage and the demo world, from the released
image:

<!-- x-release-please-start-version -->
```bash
git clone --branch v0.2.0 https://github.com/cipherfort/fortproof && cd fortproof
AAP_IMAGE=ghcr.io/cipherfort/fortproof:v0.2.0 deploy/compose/setup.sh
```
<!-- x-release-please-end -->

What runs and how to stop it: [deploy/compose/README.md](../../deploy/compose/README.md). Use it to evaluate, not for
production.
