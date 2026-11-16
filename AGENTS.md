# kbox agent notes

## Git hooks: every enforced restriction

`make install-hooks` symlinks `scripts/*.hook` into `.git/hooks`. The build
target `.git/hooks/pre-commit` calls it on the first build.

Every hook exits 0 when `CI` is set in the environment or `/home/runner/work`
exists (`check_ci` in `scripts/common.sh`). The rules below therefore run on
developer machines only, plus the `commit-hygiene` CI job.

Never pass `--no-verify`. It disables every check in this document.

Order of execution: `pre-commit`, then `commit-msg`, then `post-commit`.
`pre-push` runs separately on push.

### pre-commit: `scripts/pre-commit.hook`

All checks below block the commit unless marked as a warning. Checks that read
C source only see newly added lines, with string literals and comments removed.

| Check | Restriction |
|---|---|
| 1 | Workspace path contains ASCII only |
| 2 | No merge conflict markers in staged files |
| 3 | Binary files staged: warning only |
| 4 | No whitespace errors (`git diff --cached --check`) |
| 5 | Changed C/H files match `.clang-format` under `clang-format-20` |
| 6 | No banned functions: `gets`, `sprintf`, `vsprintf`, `strcpy`, `stpcpy`, `strcat`, `atoi`, `atol`, `atoll`, `atof`, `mktemp`, `tmpnam`, `tempnam` |
| 7 | No new `TODO`, `FIXME`, `HACK`, or `XXX` comment |
| 8a | No non-literal format string in `printf`, `vprintf`, `fprintf`, `dprintf`, `vfprintf`, `snprintf`, `vsnprintf`. Suppress with a `format-ok` comment |
| 8b | `open()` needs `O_CLOEXEC`, `pipe()` needs `pipe2()`, `socket()` needs `SOCK_CLOEXEC`, `accept()` needs `accept4()` |
| 8c | Return `-EFOO`, never `+EFOO` |
| 8d | No `malloc()` with a multiplication. Use `calloc`, `reallocarray`, `__builtin_mul_overflow`, or a `overflow-ok` comment |
| 8e | No `%s` or `%[` without a width in `scanf` family |
| 8f | No `strtok`, `asctime`, `ctime`, `gmtime`, `localtime`. Use the `_r` variant |
| 9 | `make check-syntax` passes. Runs on Linux with `.config` present, skipped otherwise |
| 10 | `cppcheck --enable=all --error-exitcode=1` passes on changed `.c` files. A changed header widens this to every `src/*.c` |
| 11 | Staged filenames contain ASCII only |

`clang-format-20` and `cppcheck` must be installed whenever a C/H file is
staged. The hook exits 1 when either is missing.

### commit-msg: `scripts/commit-msg.hook`

Every row blocks the commit.

| Restriction |
|---|
| Blank line between subject and body |
| Subject at most 72 characters. Warning above 50 |
| Subject starts with an uppercase letter |
| Subject does not end with a period |
| Subject starts with an imperative verb. The hook holds the denylist: `added`, `fixed`, `updated`, `changed`, `removed`, `refactored`, `implemented`, `created`, `moved`, `renamed`, `tested`, `bumped`, and similar past or progressive forms |
| Subject holds more than one word |
| No conventional-commit prefix such as `feat:`, `fix(scope):`, or `chore!:` |
| Subject does not start with whitespace |
| No backtick anywhere in the message |
| No placeholder padding: no 4 or more identical letters in a row in the subject |

Warnings only:

- Body line longer than 72 characters. URLs and trailers (`Change-Id:`,
  `Signed-off-by:`, `Reviewed-by:`, and similar) are exempt.

Exemptions:

- An empty subject skips validation.
- A `fixup!` commit skips validation.
- A leading `squash! ` is stripped before validation.

The hook appends a `Change-Id:` trailer when the message has none. No check
reads that trailer at push time.

### post-commit: `scripts/post-commit.hook`

Runs `scripts/vanity-hash.py` on HEAD after every commit. The script appends
invisible space and tab padding to the message body until the commit SHA starts
with `0000`. Override the prefix with `git config kbox.vanity-prefix`. The search
costs about 65K SHA-1 attempts per commit.

Consequence: the padding joins the subject line when the message has no body. A
long subject can pass `commit-msg` and then grow past 72 characters inside the
created commit.

### pre-push: `scripts/pre-push.hook` and `scripts/check-commitlog.sh`

The hook validates only the commits being pushed: `remote..local` for a known
remote ref, the oldest new commit and up for a new branch. Merge commits are
skipped. Validation covers commits after the cutoff `4a46a13`.

Every row blocks the push.

| Restriction |
|---|
| Subject shorter than 80 characters |
| Subject starts with an uppercase letter |
| Subject does not end with a period |
| Commit SHA starts with `0000` for every commit after `5aa6396` |

Warnings only:

- Subject is 10 characters or shorter.
- Subject starts with `WIP:`.

Prerequisite: the cutoff commit `4a46a13` must exist in the local object store.
The hook aborts when it is missing. Run `git fetch` first.

A rebase or amend rewrites the SHA of every descendant. `post-commit` repairs
HEAD only. Run `scripts/check-commitlog.sh` after a rebase to find the commits
that lost the `0000` prefix, and `scripts/vanity-hash.py` on each of them.

### CI: `commit-hygiene` job

`.github/workflows/build-kbox.yml` runs `scripts/check-commitlog.sh` again. It
derives the range from `pull_request.base.sha..head.sha` or `before..after` and
fails the job when the local rules fail.
