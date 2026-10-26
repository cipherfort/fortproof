# Changelog

All notable changes, newest first. From 0.1.0 on this file is maintained by release-please from Conventional Commit
messages (`feat:`, `fix:`, `docs:` ...); see [RELEASING.md](RELEASING.md).

## [0.2.0](https://github.com/cipherfort/fortproof/compare/v0.1.5...v0.2.0) (2026-10-26)


### Features

* an "I tried FortProof" feedback form ([#114](https://github.com/cipherfort/fortproof/issues/114)) ([d958e4a](https://github.com/cipherfort/fortproof/commit/d958e4a3e7b8db6a784170c5ef22d9b4ad163b2f))

## [0.1.5](https://github.com/cipherfort/fortproof/compare/v0.1.4...v0.1.5) (2026-10-21)


### Bug Fixes

* sign-out ends the identity provider's session; clearer first view for people without a team ([#70](https://github.com/cipherfort/fortproof/issues/70)) ([dea552a](https://github.com/cipherfort/fortproof/commit/dea552a9cd801a62b6e9a6e64782fc98e330b07e))

## [0.1.4](https://github.com/cipherfort/fortproof/compare/v0.1.3...v0.1.4) (2026-10-21)


### Bug Fixes

* **deps:** update certifi to 2026.10.19 (GHSA-6q48-6c7w-9gw2) ([#66](https://github.com/cipherfort/fortproof/issues/66)) ([216ce00](https://github.com/cipherfort/fortproof/commit/216ce009c65b3ba7551e360766c57ac284bcec68))
* **release:** attach the chart's signature and the image's provenance to each GitHub release ([#65](https://github.com/cipherfort/fortproof/issues/65)) ([f5c03bf](https://github.com/cipherfort/fortproof/commit/f5c03bfd9a2b6fde20010a97e94bf1a37538bb16))

## [0.1.3](https://github.com/cipherfort/fortproof/compare/v0.1.2...v0.1.3) (2026-10-20)


### Bug Fixes

* **release:** log in to GHCR for cosign before signing the chart ([#59](https://github.com/cipherfort/fortproof/issues/59)) ([95f7f3b](https://github.com/cipherfort/fortproof/commit/95f7f3bf399b849fb2a7ca30968b1e0ce5601de1))

## [0.1.2](https://github.com/cipherfort/fortproof/compare/v0.1.1...v0.1.2) (2026-10-20)


### Bug Fixes

* **image:** build gh from its release tag so the binary carries its real version ([#56](https://github.com/cipherfort/fortproof/issues/56)) ([0e3a89b](https://github.com/cipherfort/fortproof/commit/0e3a89bd018ac24496c27ec9d0f8f101a0c982c7))

## [0.1.1](https://github.com/cipherfort/fortproof/compare/v0.1.0...v0.1.1) (2026-10-20)


### Bug Fixes

* **image:** build the bundled gh from source with patched dependencies ([#53](https://github.com/cipherfort/fortproof/issues/53)) ([98a9cf9](https://github.com/cipherfort/fortproof/commit/98a9cf98f1de6a90efe978c20561cf049de6be84))

## 0.1.0 (2026-10-20)

First public preview: the evidence engine, all 48 control evaluators, GitHub and GitLab, shipped security pipelines
and components, built-in vulnerability intelligence, exceptions, assessments, administration, the web UI, the Helm
chart and the Compose evaluation stack. Tested end to end on a real GitHub organization
([guide](docs/guides/github-e2e.md)). See [ROADMAP.md](ROADMAP.md) for what 1.0 adds.

The project was called Attestra before its first release; it was renamed FortProof to avoid a clash with an existing
security product of that name.


### ⚠ BREAKING CHANGES

* evidence manifests and attestations use the predicate type https://fortproof.dev/attestation/evidence/v1; the old one is refused. Nothing was released under the old name.

### Features

* **github:** pick up workflow runs whose webhook never arrived ([#45](https://github.com/cipherfort/fortproof/issues/45)) ([ed1459f](https://github.com/cipherfort/fortproof/commit/ed1459f262c476ac1ca7db4fdc2f08575f531166))
* monthly posture snapshots, trends and dashboard read models (UI-3) ([#34](https://github.com/cipherfort/fortproof/issues/34)) ([b5325b8](https://github.com/cipherfort/fortproof/commit/b5325b88219aa46f9041adc6f9f3f87f9e170329))
* rename the project to FortProof ([#40](https://github.com/cipherfort/fortproof/issues/40)) ([fa06d30](https://github.com/cipherfort/fortproof/commit/fa06d3081c9b7161594270c3060a22c445a04a2a))
* **ui:** controls catalogue, maturity roll-up, supply chain (UI-6) ([#37](https://github.com/cipherfort/fortproof/issues/37)) ([c1086c4](https://github.com/cipherfort/fortproof/commit/c1086c4edac541281f31d3f5d2d97ed9f5d0a405))
* **ui:** evidence explorer with verification chain, global findings (UI-5) ([#36](https://github.com/cipherfort/fortproof/issues/36)) ([6203cc7](https://github.com/cipherfort/fortproof/commit/6203cc7f0af72152b0d0e552916d0e58bd396ba6))
* **ui:** exceptions, assessments, leadership, integrations, admin and onboarding (UI-7) ([#38](https://github.com/cipherfort/fortproof/issues/38)) ([6252661](https://github.com/cipherfort/fortproof/commit/6252661834f5c497c4f830edffb0638041da7fb0))
* **ui:** launch assets, bundle budget, keyboard and reduced-motion checks (UI-8) ([#39](https://github.com/cipherfort/fortproof/issues/39)) ([fa96f90](https://github.com/cipherfort/fortproof/commit/fa96f9026a3cfc49c9bd323e92b8b5b7e8c00776))


### Bug Fixes

* **attestation:** accept the evidence predicate the shipped workflows sign ([#46](https://github.com/cipherfort/fortproof/issues/46)) ([3db0fd0](https://github.com/cipherfort/fortproof/commit/3db0fd07892e70bc4495cc1041ce89b2faed881d))
* **findings:** close dependency findings when the next SBOM drops the component ([#47](https://github.com/cipherfort/fortproof/issues/47)) ([37e8958](https://github.com/cipherfort/fortproof/commit/37e8958357f31175af9e3e64f6db87c432d30349))
* **gitlab-issues:** create labels before the issue so deduplication cannot break ([#30](https://github.com/cipherfort/fortproof/issues/30)) ([372adb5](https://github.com/cipherfort/fortproof/commit/372adb5b0faae0f7aa525a29e68c571e4f4b0f8c))
* **worker:** keep the scheduler sweep running ([#43](https://github.com/cipherfort/fortproof/issues/43)) ([bd734c0](https://github.com/cipherfort/fortproof/commit/bd734c0f654c031b152dfc10f1aa8e7545605e4e))
