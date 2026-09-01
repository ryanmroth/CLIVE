# Source Manifest

Upstream repository: https://github.com/aio-libs/aiohttp

No aiohttp source is redistributed in this evidence directory.

## Candidate A

- Tag: `v3.9.1`
- Release commit: `6333c026422c6b0fe57ff63cde4104e2d00f47f4`
- Release: https://github.com/aio-libs/aiohttp/releases/tag/v3.9.1
- Experimental status after unblinding: **vulnerable** for the primary ground-truth issue

## Candidate B

- Tag: `v3.9.2`
- Release commit: `24a6d64966d99182e95f5d3a29541ef2fec397ad`
- Release: https://github.com/aio-libs/aiohttp/releases/tag/v3.9.2
- Experimental status after unblinding: **patched** for the primary ground-truth issue

## Reconstruction

```bash
git clone https://github.com/aio-libs/aiohttp.git source
cd source
git fetch --tags

mkdir -p ../candidate-a ../candidate-b

git archive v3.9.1 aiohttp | tar -x -C ../candidate-a
git archive v3.9.2 aiohttp | tar -x -C ../candidate-b
```

The audit scope was then rooted in each candidate directory.

The release commit identifiers above are the commits pointed to by the public GitHub release tags.
