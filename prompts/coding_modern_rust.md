# Modern Rust Guide (2026)

A comprehensive reference for writing idiomatic Rust targeting **edition 2024** and **stable 1.85-1.93+**.

---

## Edition 2024 (Rust 1.85+)

### Language changes

**Let chains** — `if let` and `while let` now support `&&`:

```rust
if let Some(x) = opt && x > 0 && let Ok(y) = fallible(x) {
    use_both(x, y);
}
```

**`unsafe extern` blocks** — All items in `extern` blocks are now implicitly safe to
declare. You must write `unsafe extern` when the foreign function itself is unsafe to call:

```rust
unsafe extern "C" {
    // calling this is unsafe
    fn dangerous_ffi();
}

extern "C" {
    // calling this is safe (you guarantee it's always safe)
    safe fn simple_getter() -> i32;
}
```

**`unsafe_op_in_unsafe_fn`** — Now warn-by-default. Unsafe operations inside
`unsafe fn` must be wrapped in `unsafe {}` blocks:

```rust
unsafe fn process(ptr: *const u8) -> u8 {
    // Must wrap the deref in an unsafe block
    unsafe { *ptr }
}
```

**`static mut` references denied** — Creating references to `static mut` is now a
hard error. Use `std::sync::Mutex`, `AtomicT`, or `SyncUnsafeCell` instead.

**`env::set_var` / `env::remove_var` are `unsafe`** — The environment is process-global
shared mutable state. Wrap calls in `unsafe {}` or redesign to avoid mutation.

**RPIT lifetime capture** — Return-position `impl Trait` now captures all in-scope
lifetime parameters by default. Use `+ use<'a>` to opt in to specific lifetimes:

```rust
fn foo<'a>(x: &'a str, y: &str) -> impl Display + use<'a> {
    // only captures 'a, not the anonymous lifetime of y
    x
}
```

**`gen` is a reserved keyword** — Rename any identifiers named `gen` to avoid
breakage (prefix with `r#gen` if you must).

**Resolver v3** — The default dependency resolver is now v3 (deduplicates features
across target platforms). Remove `resolver = "2"` from `Cargo.toml` — it's the default.

**Trait upcasting** — A `dyn Subtrait` can be coerced to `dyn Supertrait` without
helper methods:

```rust
trait Base {}
trait Child: Base {}

fn upcast(c: &dyn Child) -> &dyn Base {
    c // just works
}
```

**Async closures** — `async || {}` is now stable. Prefer over `|| async {}` because
the closure can borrow from its environment across `.await`:

```rust
let name = String::from("world");
let greet = async || {
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("hello {name}"); // borrows name across await
};
```

### Cargo.toml migration

```toml
[package]
edition = "2024"
rust-version = "1.85"

# resolver = "2"  ← remove, v3 is the default
```

---

## New Stable APIs (1.85 — 1.93)

| API | Since | Replaces |
|-----|-------|----------|
| `Duration::from_mins()` / `from_hours()` / `from_days()` | 1.91 | Manual `from_secs(n * 60)` |
| `Vec::pop_if(\|v\| pred(v))` | 1.86 | `.last().filter()` + `.pop()` |
| `Vec::extract_if(\|v\| pred(v))` | 1.87 | Manual drain-filter loops |
| `HashMap::extract_if` | 1.87 | `.retain()` when you need removed items |
| `HashMap::get_disjoint_mut([&k1, &k2])` | 1.86 | Unsafe or index tricks for multiple `&mut` |
| `Result::flatten()` | 1.87 | Nested `.and_then(identity)` |
| `File::lock()` / `lock_shared()` / `try_lock()` | 1.87 | `fs2` or `file-lock` crates |
| `Path::file_prefix()` | 1.87 | Manual stem splitting |
| `RwLockWriteGuard::downgrade()` | 1.87 | Drop + re-acquire |
| `std::fmt::from_fn(\|f\| write!(f, ...))` | 1.88 | Custom `Display` wrapper structs |
| `str::ceil_char_boundary(n)` | 1.86 | Manual UTF-8 scanning |
| `LazyLock` / `OnceLock` | 1.80 | `lazy_static!`, `once_cell` |
| Native `async fn` in traits | 1.75 | `#[async_trait]` proc macro |
| `#[diagnostic::on_unimplemented]` | 1.78 | — |
| `Error` trait in `core` | 1.81 | `std::error::Error` only |

### Key highlights

**`LazyLock` replaces `lazy_static!`:**

```rust
use std::sync::LazyLock;

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    Config::load().expect("config")
});
```

**Native async traits** (no more `#[async_trait]` for static dispatch):

```rust
trait Service {
    async fn call(&self, req: Request) -> Response;
}
```

Only use the `async-trait` crate when you need `dyn Service` (dynamic dispatch).

---

## Blessed Crate Stack (2026)

### Core ecosystem

| Category | Crate | Notes |
|----------|-------|-------|
| Async runtime | `tokio` | De-facto standard. Use `rt-multi-thread` for servers. |
| Web framework | `axum` | Tower-based, extracted from hyper. |
| HTTP client | `reqwest` | Use `rustls-tls` feature, not `native-tls`. |
| Serialization | `serde` + `serde_json` | Ubiquitous. |
| Logging | `tracing` + `tracing-subscriber` | Structured, span-based. Replaces `log`. |
| CLI | `clap` (derive) | `#[derive(Parser)]`. |
| SQL (async) | `sqlx` | Compile-time checked queries. |
| SQL (sync) | `rusqlite` | Use `bundled` feature for embedded SQLite. |
| Error (libs) | `thiserror` 2.0 | `#[derive(Error)]` with `#[error(...)]`. |
| Error (apps) | `anyhow` | `.context("what failed")` chains. |
| Date/time | `jiff` | Correct timezone handling. Replaces `chrono` for new code. |
| Parallelism | `rayon` | Data-parallel iterators. |
| UUID | `uuid` | Use `v7` feature for time-sortable IDs. |
| Testing | `cargo-nextest` | Parallel, per-test process isolation. |
| Linting | `clippy` (built-in) | Shipped with `rustup`. |

### Deprecated / replaced

| Don't use | Use instead | Why |
|-----------|-------------|-----|
| `lazy_static` | `std::sync::LazyLock` | In std since 1.80. |
| `once_cell` | `std::sync::OnceLock` | In std since 1.80. |
| `#[async_trait]` | Native async traits | In language since 1.75 (for static dispatch). |
| `async-std` | `smol` or `tokio` | `async-std` is unmaintained. |
| `chrono` (new code) | `jiff` | Better timezone semantics, smaller API surface. |
| `failure` | `thiserror` / `anyhow` | Abandoned since 2019. |
| `reqwest` default-tls | `reqwest` + `rustls-tls` | Pure Rust, no OpenSSL dependency. |

---

## Ownership & Borrowing

### Function parameter guidelines

| You need to… | Take | Example |
|---|---|---|
| Read the data | `&T` | `fn len(s: &str) -> usize` |
| Mutate in place | `&mut T` | `fn push(v: &mut Vec<i32>, x: i32)` |
| Take ownership (store, move, consume) | `T` | `fn spawn(f: impl FnOnce() + Send + 'static)` |
| Accept multiple input types | `impl Into<T>` | `fn set_name(n: impl Into<String>)` |
| Return owned data | `T` (not `&T`) | `fn create() -> Vec<u8>` |

**Default to borrowing.** Only take ownership when you need to store,
move into another thread, or the callee genuinely consumes the value.

### Returning references — must borrow from an input

A function can only return a reference if it borrows from a parameter
(or from `&self` / `'static` data). Returning a reference to a local is
always a compile error:

```rust
// BAD — s is owned, dropped at end of function
fn first_word(s: String) -> &str {
    &s[..s.find(' ').unwrap_or(s.len())]  // E0106/E0515
}

// GOOD — borrow from the caller's data
fn first_word(s: &str) -> &str {
    &s[..s.find(' ').unwrap_or(s.len())]
}
```

### Shared ownership

| Need | Use | Notes |
|------|-----|-------|
| Multiple owners, immutable | `Arc<T>` | Thread-safe; cheap clone |
| Multiple owners, mutable | `Arc<Mutex<T>>` | Lock before access |
| Borrow-or-own flexibility | `Cow<'a, T>` | Avoids allocation when borrowing suffices |

Reach for `Arc` at async task boundaries. Prefer `Cow<str>` over
`String` when a function sometimes borrows and sometimes allocates.

---

## Lifetimes

### Core rule

A reference `&'a T` promises the data lives at least as long as `'a`.
The compiler infers lifetimes when possible (elision), but you must
annotate when there's ambiguity.

### Elision rules (quick reference)

1. Each input reference gets its own lifetime.
2. If there's exactly one input lifetime, output references get that
   lifetime.
3. If one input is `&self` or `&mut self`, output references get `self`'s
   lifetime.

When these rules don't resolve the output lifetime, you must annotate:

```rust
// Two input references — compiler can't guess which the output borrows from
fn longer<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.len() >= b.len() { a } else { b }
}
```

### Common pitfalls

**Returning an iterator over owned data.** The iterator borrows the
collection, but the collection is moved into the function — nothing to
borrow from:

```rust
// BAD — s is consumed, iterator would dangle
fn chars_of(s: String) -> impl Iterator<Item = char> {
    s.chars()  // borrows s, but s is dropped → E0597
}

// GOOD — return an owned iterator
fn chars_of(s: String) -> impl Iterator<Item = char> {
    s.into_chars()  // ERROR: this method doesn't exist!
    // Real fix: change the API to borrow, or collect
}

// Option A: borrow from the caller
fn chars_of(s: &str) -> impl Iterator<Item = char> + '_ {
    s.chars()
}

// Option B: return a Vec (allocates, but owned)
fn chars_of(s: String) -> Vec<char> {
    s.chars().collect()
}
```

**Storing references in structs** — the struct's lifetime is tied to the
reference source. Prefer owned data in structs unless the struct is
explicitly short-lived:

```rust
// Fragile — ties Config's lifetime to the &str source
struct Config<'a> { name: &'a str }

// Simpler — no lifetime parameter
struct Config { name: String }
```

**RPIT lifetime capture (Edition 2024)** — see Edition 2024 section above.
In edition 2024, `impl Trait` captures all in-scope lifetimes by default.
Use `+ use<'a>` to narrow capture when needed.

---

## Traits & Generics

### Common derive sets

```rust
// Data types — derive liberally
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

// Error types
#[derive(Debug, thiserror::Error)]
pub enum AppError { /* ... */ }

// Config / serializable types
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config { /* ... */ }
```

Always derive `Debug`. Add `Clone`, `PartialEq`, `Eq`, `Hash` when the
type will be used in collections or comparisons.

### `impl Trait` vs generics vs `dyn Trait`

| Approach | When to use | Trait objects? |
|----------|-------------|---------------|
| `fn foo(x: impl Trait)` | One concrete type, caller chooses | No (monomorphized) |
| `fn foo<T: Trait>(x: T)` | Need `T` in multiple positions or `where` clause | No (monomorphized) |
| `fn foo(x: &dyn Trait)` | Heterogeneous collection, plugin architecture | Yes (dynamic dispatch) |
| `fn foo(x: Box<dyn Trait>)` | Owned trait object, returned from factory | Yes (heap-allocated) |

**Prefer generics** (static dispatch) by default. Use `dyn Trait` only
when you need type erasure (heterogeneous lists, reducing compile times
in large codebases, or returning different concrete types).

### Trait bounds — keep them readable

```rust
// Inline bounds — fine for 1-2 simple constraints
fn serialize<T: Serialize + Debug>(val: &T) -> String { /* ... */ }

// Where clauses — prefer for complex bounds
fn process<T, E>(input: T) -> Result<T::Output, E>
where
    T: Transform + Send + 'static,
    E: From<T::Error> + From<io::Error>,
{
    // ...
}
```

### Supertraits

```rust
// Any Repository must also be Send + Sync (for use across async tasks)
trait Repository: Send + Sync {
    async fn get(&self, id: &str) -> Option<Record>;
}
```

### Key marker traits

| Trait | Meaning | When it matters |
|-------|---------|-----------------|
| `Send` | Safe to transfer across threads | `tokio::spawn`, `thread::spawn` |
| `Sync` | Safe to reference from multiple threads | `Arc<T>` requires `T: Send + Sync` |
| `'static` | Contains no non-static references | Task spawning, thread boundaries |
| `Sized` | Size known at compile time | Default bound; opt out with `?Sized` |
| `Unpin` | Can be moved after being pinned | Futures, `Pin<&mut T>` |

---

## Type Conversions

### Infallible conversions — `From` / `Into`

```rust
// Implement From — you get Into for free
impl From<UserId> for String {
    fn from(id: UserId) -> Self { id.0 }
}

// Accept broad input via Into
fn greet(name: impl Into<String>) {
    let name = name.into();
    println!("Hello, {name}");
}
greet("world");         // &str → String
greet(String::new());   // String → String (no-op)
```

### Fallible conversions — `TryFrom` / `TryInto`

```rust
impl TryFrom<u64> for Port {
    type Error = PortError;
    fn try_from(n: u64) -> Result<Self, Self::Error> {
        u16::try_from(n).ok()
            .and_then(|p| (1..=65535).contains(&p).then_some(Port(p)))
            .ok_or(PortError::OutOfRange(n))
    }
}
```

**Rule**: If the conversion can fail or lose data, use `TryFrom`, not
`From`.

### Cheap reference conversions — `AsRef` / `AsMut`

```rust
// Accept anything that can cheaply become a &Path
fn read_config(path: impl AsRef<Path>) -> Result<Config> {
    let text = std::fs::read_to_string(path.as_ref())?;
    // ...
}
read_config("config.toml");           // &str → &Path
read_config(PathBuf::from("/etc"));   // PathBuf → &Path
```

### String type cheat sheet

| Type | Owned? | Use when |
|------|--------|----------|
| `&str` | No | Reading string data; function parameters |
| `String` | Yes | Building, modifying, storing, returning |
| `Cow<'a, str>` | Either | Conditionally allocating (parsing, formatting) |
| `&[u8]` / `Vec<u8>` | No / Yes | Binary data, not guaranteed UTF-8 |

```rust
// Flexible function that avoids unnecessary allocation
fn normalize(input: &str) -> Cow<'_, str> {
    if input.contains('\t') {
        Cow::Owned(input.replace('\t', "    "))
    } else {
        Cow::Borrowed(input)
    }
}
```

---

## Error Handling

### Libraries — `thiserror` 2.0

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("database query failed")]
    Db(#[from] sqlx::Error),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("not found: {entity} with id {id}")]
    NotFound { entity: &'static str, id: String },
}
```

### Applications — `anyhow`

```rust
use anyhow::{Context, Result, bail, ensure};

fn load_config(path: &Path) -> Result<Config> {
    ensure!(path.exists(), "config file not found: {}", path.display());

    let text = std::fs::read_to_string(path)
        .context("failed to read config file")?;

    let config: Config = toml::from_str(&text)
        .context("failed to parse config TOML")?;

    if config.workers == 0 {
        bail!("workers must be > 0");
    }

    Ok(config)
}
```

### Rules of thumb

- **Libraries** expose typed errors (`thiserror`) so callers can match.
- **Applications** use `anyhow::Result` — callers are humans reading logs.
- **Never** use `Box<dyn Error>` as a public API error type.
- Add `.context()` at **every** `?` where the surrounding operation isn't obvious.
- Use `bail!` for early returns, `ensure!` for preconditions.

---

## Async Patterns

### Use async only when needed

Default to synchronous code. Reach for async only when you genuinely have
concurrent I/O (network servers, fan-out HTTP calls, etc.).

### Never block the async runtime

```rust
// BAD — blocks the tokio executor thread
let data = std::fs::read_to_string("big.json")?;

// GOOD — offload to a blocking thread pool
let data = tokio::task::spawn_blocking(|| {
    std::fs::read_to_string("big.json")
}).await??;
```

### CPU-bound work

Use `rayon` or `spawn_blocking`, never run tight loops on async threads:

```rust
let result = tokio::task::spawn_blocking(move || {
    heavy_computation(&input)
}).await?;
```

### `Send + 'static` bounds

Values moved into `tokio::spawn` must be `Send + 'static`. This means:
- No borrowed references across `.await` (use `Arc` or clone).
- No `Rc`, `Cell`, or non-Send types.

### Cancellation safety

`tokio::select!` drops unfinished futures. Use `tokio::pin!` and loop-select
patterns for stateful futures. Prefer cancellation-safe methods like
`recv()` over `next()` on streams.

### Structured concurrency

Prefer `JoinSet` over spawning unbounded tasks:

```rust
let mut set = tokio::task::JoinSet::new();
for url in urls {
    set.spawn(fetch(url));
}
while let Some(result) = set.join_next().await {
    handle(result??);
}
```

---

## Anti-Patterns

### Excessive `.clone()`

If you're cloning to satisfy the borrow checker, reconsider your data ownership.
Use `&str` instead of `String`, `Arc<T>` for shared ownership, or restructure
to avoid the conflict.

### `unwrap()` outside tests

Use `unwrap()` freely in tests. In production code, use `?`, `.expect("reason")`,
or handle the error.

### Boolean parameters

```rust
// BAD — what does `true` mean at the call site?
process(data, true, false);

// GOOD — use enums or builder pattern
process(data, Mode::Strict, Validate::Skip);
```

### `..Default::default()` struct update footgun

Adding a field to a struct won't cause a compile error at construction sites
that use `..Default::default()`. Prefer explicit construction.

### Catch-all `_` on owned enums

```rust
// BAD — silently ignores new variants when the enum grows
match event {
    Event::Click => handle_click(),
    _ => {}
}

// GOOD — exhaustive, compiler warns on new variants
match event {
    Event::Click => handle_click(),
    Event::Hover => {}
}
```

### `From` that should be `TryFrom`

If the conversion can fail or lose data, implement `TryFrom`, not `From`.

### `#![deny(warnings)]` in libraries

This breaks downstream builds when the compiler adds new lints. Use
`#![warn(clippy::all)]` instead, and deny only in CI via `RUSTFLAGS`.

### Deref polymorphism

Don't implement `Deref` to simulate inheritance. It's confusing and
breaks IDE tooling. Use composition or traits instead.

---

## Defensive Patterns

### `#[must_use]`

Apply to functions whose return value should not be silently ignored:

```rust
#[must_use]
fn validate(input: &str) -> Result<(), ValidationError> { ... }
```

### `#[non_exhaustive]`

Prevent downstream code from exhaustively matching or constructing your types,
allowing you to add variants/fields without a semver bump:

```rust
#[non_exhaustive]
pub enum ApiError {
    NotFound,
    RateLimited,
}

#[non_exhaustive]
pub struct Config {
    pub timeout: Duration,
    pub retries: u32,
}
```

### `#[serde(deny_unknown_fields)]`

Catch typos and schema drift in config files / API payloads:

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    host: String,
    port: u16,
}
```

### Private fields with constructors

Preserve invariants by keeping fields private and exposing constructors:

```rust
pub struct Port(u16);

impl Port {
    pub fn new(n: u16) -> Option<Self> {
        (1..=65535).contains(&n).then_some(Self(n))
    }

    pub fn get(&self) -> u16 { self.0 }
}
```

### Exhaustive pattern matching

Prefer matching all variants over `_` wildcards on enums you own.
The compiler will flag new variants at every match site.

---

## Project Setup

### Recommended `Cargo.toml`

```toml
[package]
name = "my-project"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"

[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
# Lint groups — broad coverage
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }

# Pedantic overrides — disable noisy / false-positive lints
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"

# Restriction lints — enforce quality patterns
# Error handling: force ? or .expect("reason"), not .unwrap()
unwrap_used = "warn"
panic = "warn"
unwrap_in_result = "warn"
# Clarity: make intent explicit
clone_on_ref_ptr = "warn"            # Arc::clone(&x) not x.clone()
str_to_string = "warn"              # .to_owned() not .to_string() for &str
string_to_string = "warn"           # catch meaningless String → String
wildcard_enum_match_arm = "warn"    # match all variants, no catch-all _
# Completeness: catch placeholders and debug leftovers
dbg_macro = "warn"
todo = "warn"
unimplemented = "warn"

[profile.release]
lto = "thin"
strip = true
```

### `clippy.toml`

Place at the project root alongside `Cargo.toml`:

```toml
msrv = "1.85"

# Allow unwrap/expect in #[cfg(test)] — strict in production, relaxed in tests
allow-unwrap-in-tests = true

# Tighter thresholds than defaults
too-many-arguments-threshold = 5     # default 7
cognitive-complexity-threshold = 25   # default 25 (raise if needed)
```

### `rustfmt.toml`

```toml
edition = "2024"
max_width = 100
imports_granularity = "Module"       # group imports by module
group_imports = "StdExternalCrate"   # separate std / external / crate imports
```

This produces clean import blocks:

```rust
use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;

use crate::config::Settings;
```

### Workspace setup

```toml
[workspace]
members = ["crates/*"]

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
unwrap_used = "warn"
panic = "warn"
unwrap_in_result = "warn"
clone_on_ref_ptr = "warn"
str_to_string = "warn"
string_to_string = "warn"
wildcard_enum_match_arm = "warn"
dbg_macro = "warn"
todo = "warn"
unimplemented = "warn"
```

Each member inherits lints:

```toml
[lints]
workspace = true
```

---

## Concurrency Primitives

| Need | Use |
|------|-----|
| Interior mutability (single-thread) | `Cell<T>`, `RefCell<T>` |
| Shared state (sync) | `Arc<Mutex<T>>` or `Arc<RwLock<T>>` |
| Shared state (async) | `tokio::sync::Mutex` / `RwLock` |
| Atomic counters/flags | `AtomicBool`, `AtomicUsize`, etc. |
| One-time init | `OnceLock`, `LazyLock` |
| Channel (bounded) | `tokio::sync::mpsc` / `crossbeam::channel` |
| Channel (oneshot) | `tokio::sync::oneshot` |
| Broadcast | `tokio::sync::broadcast` |
| Concurrent map | `dashmap` or `papaya` |

### `std::sync::Mutex` vs `tokio::sync::Mutex`

Use `std::sync::Mutex` when the critical section is short and never holds
across `.await`. Use `tokio::sync::Mutex` only when you must hold the lock
across an await point — it's slower but won't deadlock the runtime.

---

## Testing

### Test organization

- Unit tests: `#[cfg(test)] mod tests` inline in each file.
- Integration tests: `tests/` directory for cross-module behavior.
- Use `cargo nextest run` for parallel, isolated test execution.

### Useful patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_name_states_expectation() {
        let result = parse("valid input");
        assert_eq!(result, Expected::Value(42));
    }

    #[tokio::test]
    async fn async_test_with_tokio() {
        let resp = client.get("/health").await;
        assert!(resp.status().is_success());
    }
}
```

### Property testing

Use `proptest` for generative testing of pure functions:

```rust
proptest! {
    #[test]
    fn roundtrip_serialization(input in ".*") {
        let encoded = encode(&input);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(input, decoded);
    }
}
```
