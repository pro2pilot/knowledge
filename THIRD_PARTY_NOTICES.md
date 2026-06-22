# Third-Party Notices

`.knowledge` does not vendor memory-provider code in this package.

## Mem0 OSS

- Provider id: `mem0-oss`
- Package: `mem0ai`
- Pinned version in manifest: `mem0ai==2.0.4`
- Source: https://github.com/mem0ai/mem0
- Docs: https://docs.mem0.ai/open-source/overview
- License: Apache-2.0
- Bundled: no
- Install method: explicit user-run package install; `.knowledge` records approval receipts only.
- User data path: `<stateRoot>/external_memory/mem0`
- Update policy: pinned explicit update receipt, no silent update.

## Pinecone

- Provider id: `pinecone`
- Source: https://www.pinecone.io/
- Terms: https://www.pinecone.io/terms/
- Bundled: no
- Install method: environment-configured optional retrieval bridge.
- User data path: provider-managed or configured vector index.
- Update policy: external service/client managed by user.

## Paid Inspector Providers

Graphiti and Zep provider contracts are modeled in the paid Inspector directory. They are not bundled into the free `.knowledge` core.
