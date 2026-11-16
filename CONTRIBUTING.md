# Contributing

Thanks for your interest in `ocd`, the OneCloud CLI.

## Before you start

- Security problem: do not open an issue or a pull request, follow
  [SECURITY.md](SECURITY.md).
- `ocd` is the client of the OneCloud managed platform (portal, identity
  provider, access gateway). A change that also needs a platform change cannot
  be finished in this repository alone: open an issue first.

## Build and test

You need the Go release named by the `go` line of `go.mod`, or newer.

```bash
make vet test     # static checks and unit tests
make build        # -> bin/ocd
make cross        # every release target into dist/
```

The tests run offline against local stand-ins. They never sign in to a real
OneCloud cluster.

## Pull requests

- One change per pull request, with a test that fails without it.
- Give the pull request a conventional title: `feat(scope): ...`,
  `fix(scope): ...`, `docs: ...`. The title becomes the commit on `main` and
  decides the next version (`feat` minor, `fix` patch, `!` major).
- Run `make vet test` before you push.
- Do not put credentials, tenant names or addresses of a real deployment in
  code, tests or examples. Use `demo-000001`, `example.com` and private
  documentation addresses such as `10.0.0.12`.
- Builds are not started automatically for pull requests from forks. A
  maintainer reviews the change first.

## Dependencies and licenses

Every release archive ships the license texts of everything linked into the
binary. After adding, removing or updating a dependency:

```bash
go mod tidy
make notices      # rewrites NOTICE and THIRD_PARTY_NOTICES.md
make vuln
```

Commit the regenerated files with the change. `make test` fails when they are
out of date, when a linked module ships no license file, or when its license
is not one of those already listed in the summary of
`THIRD_PARTY_NOTICES.md` (Apache-2.0, MIT, BSD, ISC, MPL-2.0, Unlicense,
CC0-1.0). A dependency under any other license needs a maintainer decision
before the pull request can be merged.

## License of contributions

`ocd` is licensed under the Apache License 2.0. As section 5 of that license
states, a contribution you submit to this repository is provided under the
same license, unless you say otherwise in writing.
