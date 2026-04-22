# Rule Operator Parity Matrix (Go -> Rust)

Scope:
- Go source of truth: daemon/rule/operator.go, daemon/rule/operator_lists.go, daemon/rule/operator_aliases.go, daemon/rule/rule.go
- Rust matcher path: crates/daemon/src/services/rule_service.rs
- Rust live reload path for list-backed operators: crates/daemon/src/workers/rule_watch_worker.rs + crates/daemon/src/workers/watch_worker_control.rs

Status legend:
- PARITY: behavior replicated in Rust verdict flow
- N/A: not active in Go runtime path (commented/TODO)

## Core operands

| Operand | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| true | unconditional true | PARITY | tests/rule_service.rs: true operator upsert/match tests |
| process.id | exact/case-insensitive simple compare | PARITY | services/rule_service.rs unit tests |
| process.path | simple/regexp with sensitive flag | PARITY | services/rule_service.rs + tests/rule_service.rs |
| process.parent.path | walk parent chain and match any | PARITY | tests/rule_service.rs parent path test |
| process.command | join args with space and compare | PARITY | services/rule_service.rs unit tests |
| process.env.<KEY> | lookup env var and compare | PARITY | tests/rule_service.rs env present/missing |
| process.hash.md5 | hash compare; when unavailable treated as match in hash operator path | PARITY | services/rule_service.rs unit tests |
| process.hash.sha1 | same semantics as md5 | PARITY | services/rule_service.rs unit tests |
| user.id | uid compare | PARITY | services/rule_service.rs unit tests |
| user.name | resolve username to uid and compare uid | PARITY | services/rule_service.rs + tests/rule_service.rs |
| source.ip | simple compare | PARITY | services/rule_service.rs unit tests |
| source.port | simple compare | PARITY | services/rule_service.rs unit tests |
| source.network | network compare against source IP | PARITY | services/rule_service.rs unit tests |
| dest.ip | simple compare | PARITY | services/rule_service.rs unit tests |
| dest.host | simple/regexp compare including empty-host edge case | PARITY | services/rule_service.rs unit tests |
| dest.port | simple and range compare | PARITY | tests/rule_service.rs range tests |
| dest.network | network compare (CIDR or alias) | PARITY | tests/rule_service.rs alias/network tests |
| protocol | Go uses upper-case protocol text in conman path | PARITY | tests/rule_service.rs protocol-sensitive + insensitive |
| iface.in | resolve interface index -> name and compare | PARITY | services/rule_service.rs unit tests |
| iface.out | resolve interface index -> name and compare | PARITY | services/rule_service.rs unit tests |

## Operator types

| Type | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| simple | exact compare with sensitivity rules | PARITY | services/rule_service.rs + tests/rule_service.rs |
| regexp | sensitive: raw regex; insensitive: lowercase pattern + lowercase candidate | PARITY | services/rule_service.rs regexp parity tests |
| list | AND semantics across children | PARITY | services/rule_service.rs list child test |
| lists | domains/domains_regexp/ips/nets/hash.md5 list-backed matching | PARITY | tests/rule_service.rs + tests/watch_workers.rs |
| network | allowed with dest.network type; alias-aware | PARITY | tests/rule_service.rs + services/rule_service.rs |
| range | min-max numeric parsing and comparison | PARITY | tests/rule_service.rs |
| complex | placeholder in Go, not active | N/A | Go comment/TODO |

## lists.* parity specifics

| Operand | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| lists.domains | hosts-file style rows (0.0.0.0/127.0.0.1), localhost exclusions, candidate lowercase only when insensitive | PARITY | tests/rule_service.rs domain list case/filter tests |
| lists.domains_regexp | compile regex lines, candidate lowercase only when insensitive | PARITY | tests/rule_service.rs regexp list case tests |
| lists.ips | simple entry lookup semantics | PARITY | services/rule_service.rs unit tests |
| lists.nets | CIDR entry match against destination IP | PARITY | services/rule_service.rs unit tests |
| lists.hash.md5 | md5 list entry match against process hash | PARITY | tests/rule_service.rs hash list test |

## Live reload and verdict propagation

| Feature | Go behavior summary | Rust status | Evidence |
|---|---|---|---|
| rule file add/remove/modify reload | live watch and reload rules | PARITY | tests/watch_workers.rs rules_watch_task_* |
| list file content updates affect verdict | monitored list sources trigger re-evaluation via reload | PARITY | tests/watch_workers.rs domains/regexp/nested list tests |
| nested list sub-rule list change propagation | list(type=list) children with lists.* update verdict | PARITY | tests/watch_workers.rs nested subrule test |

## Out-of-scope / not active

| Operand | Note |
|---|---|
| quota | commented TODO in Go |
| quota.sent.over | commented TODO in Go |
| quota.recv.over | commented TODO in Go |
