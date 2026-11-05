//! Config keys the parser does not know: a misspelt key (`[auth] mdoe = "jwt"`) is otherwise
//! ignored without a word, and the setting silently keeps its default.
//!
//! [`unknown_keys`] replays [`Config`]'s own `Deserialize` impl over the parsed TOML through a
//! deserializer that records which keys it used, so it cannot drift from the parser:
//!
//! - A struct's table: serde names its fields, so any other key is unknown, and the closest field
//!   is the suggestion.
//! - The sections that `#[serde(flatten)]` an [`OutboundCfg`]: serde reads them as a map and names
//!   no fields. Their own fields are read with their types; anything else is buffered for the
//!   flattened struct without one. So a buffered key that is not one of [`OutboundCfg`]'s is
//!   unknown. With no field list to suggest from, each one-character edit of the key is tried by
//!   reading the config again with the key renamed.
//!
//! Only the config file is checked; a pushed policy is the control plane's to validate (it can call
//! [`unknown_keys`] on the document).

use std::cell::RefCell;
use std::fmt;

use serde::de::DeserializeOwned;
use serde::de::{
    self, DeserializeSeed, Deserializer, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};
use serde::Deserialize;
use toml::Value;

use crate::config::{Config, OutboundCfg};

type Error = de::value::Error;

/// A key the config parser ignores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// Where it is, e.g. `auth.mdoe` or `upstreams[1].health_check.paht`.
    pub path: String,
    /// The known key it is closest to, written the same way, when one is close.
    pub suggestion: Option<String>,
}

impl fmt::Display for UnknownKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.suggestion {
            Some(s) => write!(f, "unknown key {} (did you mean {s}?)", self.path),
            None => write!(f, "unknown key {}", self.path),
        }
    }
}

/// The keys in `raw` (a config file's text) that the parser ignores, in file order by table.
/// Empty when `raw` does not parse: the parser reports that itself. Empty too, with a warning, in
/// the case [`check`] returns `None`.
pub fn unknown_keys(raw: &str) -> Vec<UnknownKey> {
    check(raw).unwrap_or_else(|| {
        tracing::warn!(
            "unknown config keys were not checked: this config parses, but the check could not \
             read it again (a gap in eggrd, not in the file)"
        );
        Vec::new()
    })
}

/// [`unknown_keys`], or `None` when `raw` is a config the parser accepts that this check cannot
/// read again: a gap here, which would otherwise look like a file with no unknown keys.
pub fn check(raw: &str) -> Option<Vec<UnknownKey>> {
    unknown_keys_as::<Config>(raw)
}

/// [`check`], for `raw` read as a `T`.
fn unknown_keys_as<T: DeserializeOwned>(raw: &str) -> Option<Vec<UnknownKey>> {
    let Ok(root) = raw.parse::<toml::Table>().map(Value::Table) else {
        return Some(Vec::new());
    };
    let Some(report) = walk::<T>(&root) else {
        // The parser refuses it too, and says why. If it accepts it, the replay has a gap.
        return toml::from_str::<T>(raw).is_err().then(Vec::new);
    };
    let outbound = outbound_fields();
    let mut replays = SUGGESTION_REPLAYS;
    let mut searches = SUGGESTION_SEARCHES;
    let mut out = Vec::new();
    for (table, fields, keys) in &report.structs {
        for key in keys.iter().filter(|k| !fields.contains(&k.as_str())) {
            out.push(UnknownKey {
                path: join(table, key),
                suggestion: closest(key, fields.iter().copied()).map(|s| join(table, s)),
            });
        }
    }
    for (table, key, used) in &report.maps {
        if matches!(used, Used::Typed) || outbound.contains(&key.as_str()) {
            continue;
        }
        let known: Vec<&str> = report
            .maps
            .iter()
            .filter(|(t, _, u)| t == table && matches!(u, Used::Typed))
            .map(|(_, k, _)| k.as_str())
            .chain(outbound.iter().copied())
            .collect();
        let suggestion = closest(key, known.iter().copied())
            .map(str::to_string)
            .or_else(|| {
                searches = searches.checked_sub(1)?;
                known_neighbour::<T>(&root, table, key, &mut replays)
            });
        out.push(UnknownKey {
            path: join(table, key),
            suggestion: suggestion.map(|s| join(table, &s)),
        });
    }
    Some(out)
}

/// One step of a path: a table key, or an index into an array of tables.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Key(String),
    Index(usize),
}

type Path = Vec<Seg>;

fn join(table: &Path, key: &str) -> String {
    let mut s = String::new();
    for seg in table {
        match seg {
            Seg::Key(k) => {
                if !s.is_empty() {
                    s.push('.');
                }
                s.push_str(k);
            }
            Seg::Index(i) => s.push_str(&format!("[{i}]")),
        }
    }
    if !s.is_empty() {
        s.push('.');
    }
    s.push_str(key);
    s
}

/// How a map entry's value was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Used {
    /// Not read yet.
    No,
    /// With its type: a field the struct knows (or a real map's value).
    Typed,
    /// Without a type: buffered for a flattened struct, or skipped.
    Untyped,
}

#[derive(Debug, Default)]
struct Report {
    /// Struct tables: where, serde's field names, and the keys the file has.
    structs: Vec<(Path, &'static [&'static str], Vec<String>)>,
    /// Entries of tables read as maps: where, the key, and how its value was read.
    maps: Vec<(Path, String, Used)>,
}

/// Replay `T`'s deserialization over `root`, recording keys. `None` if it fails, which the real
/// parser would have reported.
fn walk<T: DeserializeOwned>(root: &Value) -> Option<Report> {
    let report = RefCell::new(Report::default());
    let tracker = Tracker {
        value: root,
        path: Vec::new(),
        report: &report,
        recording: true,
        slot: None,
    };
    T::deserialize(tracker).ok()?;
    Some(report.into_inner())
}

/// `OutboundCfg`'s field names, as serde knows them.
fn outbound_fields() -> &'static [&'static str] {
    struct Probe<'a>(&'a RefCell<&'static [&'static str]>);
    impl<'de> Deserializer<'de> for Probe<'_> {
        type Error = Error;
        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
            Err(de::Error::custom("probe"))
        }
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Error> {
            *self.0.borrow_mut() = fields;
            Err(de::Error::custom("probe"))
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
            option unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier
            ignored_any
        }
    }
    let fields = RefCell::new(&[][..]);
    let _ = OutboundCfg::deserialize(Probe(&fields));
    fields.into_inner()
}

/// Whether `visitor` is serde's own buffer for a value it does not know the type of yet: a key a
/// flattening struct passes on to the struct it flattens, or an untagged enum. Every other visitor
/// that reads through `deserialize_any` is a field's own type that takes several shapes (an
/// integer or `"auto"`, a URL or a table, a `toml::Value`), and reads its value with that type.
/// The one shape this cannot tell apart is an untagged enum as a field of a flattening struct
/// (one as a map's value is fine: a map's keys are not judged). `Config` has none.
fn is_buffer<'de, V: Visitor<'de>>(visitor: &V) -> bool {
    expecting(visitor) == "any value"
}

/// What `visitor` expects, as serde words it in an error: `struct ServerCfg`, `a map`.
fn expecting<'de, V: Visitor<'de>>(visitor: &V) -> String {
    (visitor as &dyn de::Expected).to_string()
}

/// How many times one check may read the config again to find suggestions, across all its keys.
/// A key costs one read, unless that read fails (a one-edit neighbour of the key is a field that
/// takes another type than its value): then each neighbour is read alone, about a thousand reads
/// at some tens of microseconds each. This runs at startup and on every reload. Past it, keys are
/// still reported, without a suggestion.
const SUGGESTION_REPLAYS: usize = 2_000;

/// How many keys one check searches neighbours for. The read with every edit in place carries a
/// thousand-odd extra keys, some milliseconds on a large config; the keys past this are reported
/// without a suggestion.
const SUGGESTION_SEARCHES: usize = 10;

/// For a key no field list is available for: a one-character edit of it (insert, delete, swap,
/// substitute) that the table at `table` reads with its type, when the config is read again with
/// the key renamed to it. Every edit is tried in one read, with all of them in place; only when
/// that read fails is each tried alone. Each read spends one of `replays`.
fn known_neighbour<T: DeserializeOwned>(
    root: &Value,
    table: &Path,
    key: &str,
    replays: &mut usize,
) -> Option<String> {
    let taken: Vec<String> = lookup(root, table)
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();
    let candidates: Vec<String> = edits1(key)
        .into_iter()
        .filter(|c| !taken.contains(c))
        .collect();
    if let Some(typed) = typed_among::<T>(root, table, key, &candidates, replays) {
        return typed.into_iter().next();
    }
    candidates.into_iter().find(|c| {
        typed_among::<T>(root, table, key, std::slice::from_ref(c), replays)
            .is_some_and(|typed| !typed.is_empty())
    })
}

/// Read the config again with `key` in `table` replaced by each of `names`, all holding its value.
/// The names the table reads with their type, in `names`' order; `None` when the read fails or
/// `replays` is spent.
fn typed_among<T: DeserializeOwned>(
    root: &Value,
    table: &Path,
    key: &str,
    names: &[String],
    replays: &mut usize,
) -> Option<Vec<String>> {
    if *replays == 0 {
        return None;
    }
    *replays -= 1;
    let mut renamed = root.clone();
    let t = lookup_mut(&mut renamed, table)?;
    let value = t.remove(key)?;
    for name in names {
        t.insert(name.clone(), value.clone());
    }
    let report = walk::<T>(&renamed)?;
    let typed = |name: &String| {
        report
            .maps
            .iter()
            .any(|(t, k, u)| t == table && k == name && *u == Used::Typed)
    };
    Some(names.iter().filter(|n| typed(n)).cloned().collect())
}

fn lookup<'v>(root: &'v Value, path: &Path) -> Option<&'v toml::Table> {
    let mut v = root;
    for seg in path {
        v = match seg {
            Seg::Key(k) => v.as_table()?.get(k)?,
            Seg::Index(i) => v.as_array()?.get(*i)?,
        };
    }
    v.as_table()
}

fn lookup_mut<'v>(root: &'v mut Value, path: &Path) -> Option<&'v mut toml::Table> {
    let mut v = root;
    for seg in path {
        v = match seg {
            Seg::Key(k) => v.as_table_mut()?.get_mut(k)?,
            Seg::Index(i) => v.as_array_mut()?.get_mut(*i)?,
        };
    }
    v.as_table_mut()
}

/// Every string one edit away from `key`, over the characters config keys use.
fn edits1(key: &str) -> Vec<String> {
    const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789_";
    let chars: Vec<char> = key.chars().collect();
    let mut out = Vec::new();
    for i in 0..chars.len() {
        let mut c = chars.clone();
        c.remove(i);
        out.push(c.iter().collect());
    }
    for i in 0..chars.len().saturating_sub(1) {
        let mut c = chars.clone();
        c.swap(i, i + 1);
        out.push(c.iter().collect());
    }
    for i in 0..chars.len() {
        for a in ALPHABET.chars() {
            let mut c = chars.clone();
            c[i] = a;
            out.push(c.iter().collect());
        }
    }
    for i in 0..=chars.len() {
        for a in ALPHABET.chars() {
            let mut c = chars.clone();
            c.insert(i, a);
            out.push(c.iter().collect());
        }
    }
    out.retain(|s: &String| !s.is_empty() && s != key);
    out.dedup();
    out
}

/// The candidate closest to `key` within a typo's distance, if any.
fn closest<'c>(key: &str, candidates: impl Iterator<Item = &'c str>) -> Option<&'c str> {
    let limit = match key.chars().count() {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    };
    candidates
        .map(|c| (distance(key, c), c))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// Edit distance with adjacent transpositions (optimal string alignment): `mdoe` is one from
/// `mode`.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// A deserializer over one TOML value that records how its tables are read.
struct Tracker<'de, 'r> {
    value: &'de Value,
    path: Path,
    report: &'r RefCell<Report>,
    /// Off inside a value read without a type (buffered or skipped): its keys are not the
    /// schema's, so nothing under it is recorded.
    recording: bool,
    /// The map entry this value belongs to, to record how it is read.
    slot: Option<usize>,
}

impl<'de, 'r> Tracker<'de, 'r> {
    fn used(&self, how: Used) {
        if let Some(i) = self.slot {
            let mut report = self.report.borrow_mut();
            let entry = &mut report.maps[i].2;
            if *entry == Used::No {
                *entry = how;
            }
        }
    }

    fn child(&self, value: &'de Value, seg: Seg, recording: bool) -> Tracker<'de, 'r> {
        let mut path = self.path.clone();
        path.push(seg);
        Tracker {
            value,
            path,
            report: self.report,
            recording,
            slot: None,
        }
    }

    /// Read the value as what it is, untyped.
    fn visit<V: Visitor<'de>>(self, visitor: V, recording: bool) -> Result<V::Value, Error> {
        match self.value {
            Value::String(s) => visitor.visit_str(s),
            Value::Integer(i) => visitor.visit_i64(*i),
            Value::Float(f) => visitor.visit_f64(*f),
            Value::Boolean(b) => visitor.visit_bool(*b),
            Value::Datetime(d) => visitor.visit_string(d.to_string()),
            Value::Array(items) => visitor.visit_seq(Seq {
                items: items.iter().enumerate(),
                parent: &self,
                recording,
            }),
            Value::Table(t) => {
                // A struct that flattens another is read as a map: its keys are the schema's. Any
                // other map's keys are the user's own (`[auth.users]`), never unknown.
                let as_map = expecting(&visitor).starts_with("struct ");
                visitor.visit_map(Map {
                    entries: t.iter(),
                    pending: None,
                    parent: &self,
                    recording,
                    as_map,
                })
            }
        }
    }
}

macro_rules! typed {
    ($($method:ident)*) => {
        $(
            fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
                self.used(Used::Typed);
                let recording = self.recording;
                self.visit(visitor, recording)
            }
        )*
    };
}

impl<'de> Deserializer<'de> for Tracker<'de, '_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if is_buffer(&visitor) {
            self.used(Used::Untyped);
            return self.visit(visitor, false);
        }
        // A type that takes several shapes reads its value with its type all the same.
        self.used(Used::Typed);
        let recording = self.recording;
        self.visit(visitor, recording)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.used(Used::Untyped);
        visitor.visit_unit()
    }

    typed! {
        deserialize_bool deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64
        deserialize_i128 deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64
        deserialize_u128 deserialize_f32 deserialize_f64 deserialize_char deserialize_str
        deserialize_string deserialize_bytes deserialize_byte_buf deserialize_unit
        deserialize_seq deserialize_identifier
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.used(Used::Typed);
        visitor.visit_some(self)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.used(Used::Typed);
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, _: usize, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.used(Used::Typed);
        let recording = self.recording;
        self.visit(visitor, recording)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.used(Used::Typed);
        let Value::Table(t) = self.value else {
            let recording = self.recording;
            return self.visit(visitor, recording);
        };
        if self.recording {
            self.report.borrow_mut().structs.push((
                self.path.clone(),
                fields,
                t.keys().cloned().collect(),
            ));
        }
        let recording = self.recording;
        visitor.visit_map(Map {
            entries: t.iter(),
            pending: None,
            parent: &self,
            recording,
            as_map: false,
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.used(Used::Typed);
        match self.value {
            Value::String(s) => visitor.visit_enum(s.as_str().into_deserializer()),
            _ => self.visit(visitor, false),
        }
    }
}

struct Seq<'a, 'de, 'r> {
    items: std::iter::Enumerate<std::slice::Iter<'de, Value>>,
    parent: &'a Tracker<'de, 'r>,
    recording: bool,
}

impl<'de> SeqAccess<'de> for Seq<'_, 'de, '_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        match self.items.next() {
            Some((i, v)) => seed
                .deserialize(self.parent.child(v, Seg::Index(i), self.recording))
                .map(Some),
            None => Ok(None),
        }
    }
}

struct Map<'a, 'de, 'r> {
    entries: toml::map::Iter<'de>,
    pending: Option<(&'de String, &'de Value)>,
    parent: &'a Tracker<'de, 'r>,
    recording: bool,
    /// Read as a map by a struct that flattens another: entries are recorded with how their
    /// values are read. A plain struct's table is judged by its field names instead, and a real
    /// map's keys are not judged at all.
    as_map: bool,
}

impl<'de> MapAccess<'de> for Map<'_, 'de, '_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.entries.next() {
            Some((k, v)) => {
                self.pending = Some((k, v));
                seed.deserialize(k.as_str().into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let (k, v) = self
            .pending
            .take()
            .ok_or_else(|| de::Error::custom("value before key"))?;
        let mut child = self.parent.child(v, Seg::Key(k.clone()), self.recording);
        if self.recording && self.as_map {
            let mut report = self.parent.report.borrow_mut();
            report
                .maps
                .push((self.parent.path.clone(), k.clone(), Used::No));
            child.slot = Some(report.maps.len() - 1);
        }
        seed.deserialize(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(raw: &str) -> Vec<String> {
        unknown_keys(raw).iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_misspelt_key_is_reported_with_the_key_it_is_closest_to() {
        assert_eq!(
            keys("[auth]\nmdoe = \"jwt\"\n"),
            ["unknown key auth.mdoe (did you mean auth.mode?)"]
        );
        assert_eq!(
            keys("[server]\nport = 8080\nheader_read_timout = \"10s\"\n"),
            ["unknown key server.header_read_timout (did you mean server.header_read_timeout?)"]
        );
        // Nothing close: reported without a guess.
        assert_eq!(
            keys("[server]\nfrobnicate = 1\n"),
            ["unknown key server.frobnicate"]
        );
        // An unknown table, and a top-level key.
        assert_eq!(
            keys("tracingg = 1\n[auht]\nmode = \"none\"\n"),
            [
                "unknown key auht (did you mean auth?)",
                "unknown key tracingg (did you mean tracing?)"
            ]
        );
    }

    #[test]
    fn keys_inside_arrays_of_tables_and_nested_tables_are_reported_by_their_path() {
        let raw = "[[upstreams]]\npath = \"/a\"\ntarget = \"http://a:1\"\n\
                   [[upstreams]]\npath = \"/b\"\ntargets = [\"http://b:1\", \"http://c:1\"]\n\
                   [upstreams.health_check]\npaht = \"/healthz\"\n";
        assert_eq!(
            keys(raw),
            ["unknown key upstreams[1].health_check.paht (did you mean upstreams[1].health_check.path?)"]
        );
        // A map's keys are the user's: never unknown. A struct inside one is checked.
        let raw = "[auth.users]\nalice = \"pw\"\n[llm]\nenabled = true\n\
                   [llm.models.\"gpt-4o\"]\ninput_per_1m = 1.0\noutput_per_m = 2.0\n";
        assert_eq!(
            keys(raw),
            ["unknown key llm.models.gpt-4o.output_per_m (did you mean llm.models.gpt-4o.output_per_1m?)"]
        );
    }

    #[test]
    fn the_flattened_sections_are_checked_too() {
        // `[control_plane]` flattens the outbound keys: serde reads it as a map and drops what it
        // does not know, so this is where a typo used to vanish.
        let raw =
            "[control_plane]\nurl = \"https://cp\"\npol_interval = \"30s\"\nproxy = \"none\"\n\
                   ca_path = \"/ca.pem\"\n";
        assert_eq!(
            keys(raw),
            ["unknown key control_plane.pol_interval (did you mean control_plane.poll_interval?)"]
        );
        // The flattened outbound keys themselves are known, in every such section.
        for section in [
            "control_plane",
            "log.ship",
            "tracing",
            "metrics.otlp",
            "auth.jwt",
            "alerts",
            "llm.telemetry",
            "tls.acme",
            "tls.acme.dns",
        ] {
            let raw = format!(
                "[{section}]\nca_path = \"/ca.pem\"\nclient_cert_path = \"/c.pem\"\n\
                 client_key_path = \"/k.pem\"\nproxy = \"none\"\n"
            );
            assert_eq!(keys(&raw), Vec::<String>::new(), "{section}");
        }
        // An unknown table is one report, not one per key under it.
        assert_eq!(
            keys("[control_plane]\nurl = \"https://cp\"\n[control_plane.retries]\nmax = 3\nwait = 1\n"),
            ["unknown key control_plane.retries"]
        );
        // A misspelt outbound key in one, suggested from the outbound names.
        assert_eq!(
            keys("[log.ship]\nca_pth = \"/ca.pem\"\n"),
            ["unknown key log.ship.ca_pth (did you mean log.ship.ca_path?)"]
        );
    }

    #[test]
    fn a_correct_config_and_one_that_does_not_parse_report_nothing() {
        assert!(keys("[server]\nport = 8080\ntrust_forwarded_for = true\n").is_empty());
        assert!(keys("").is_empty());
        assert!(
            keys("[server\nport = ").is_empty(),
            "the parser reports this"
        );
    }

    #[test]
    fn the_distance_counts_a_swap_as_one_edit() {
        assert_eq!(distance("mdoe", "mode"), 1);
        assert_eq!(distance("mode", "mode"), 0);
        assert_eq!(distance("pol_interval", "poll_interval"), 1);
        assert_eq!(distance("abc", "xyz"), 3);
        assert_eq!(closest("mdoe", ["mode", "modes"].into_iter()), Some("mode"));
        assert_eq!(closest("zzzz", ["mode"].into_iter()), None);
        assert!(edits1("ab").contains(&"ba".to_string()));
        assert!(edits1("ab").contains(&"abc".to_string()));
        assert!(!edits1("ab").contains(&"ab".to_string()));
    }

    #[test]
    fn a_value_read_first_with_its_type_stays_known() {
        // An `Option` of a type serde reads without a type (`toml::Value` here) is read typed,
        // then untyped: it is still a known field, not a buffered unknown.
        let value = Value::Integer(3);
        let report = RefCell::new(Report {
            maps: vec![(Vec::new(), "k".into(), Used::No)],
            ..Report::default()
        });
        let tracker = Tracker {
            value: &value,
            path: Vec::new(),
            report: &report,
            recording: true,
            slot: Some(0),
        };
        let read = Option::<Value>::deserialize(tracker).unwrap();
        assert_eq!(read, Some(Value::Integer(3)));
        assert_eq!(report.into_inner().maps[0].2, Used::Typed);
    }

    /// Field shapes `Config` does not have today, on a struct that flattens another, so that adding
    /// one cannot make `doctor` fail a correct config.
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Shapes {
        section: Flattening,
        #[serde(default)]
        labels: std::collections::BTreeMap<String, serde_json::Value>,
        /// Values serde reads through its own buffer, as it does every untagged enum.
        #[serde(default)]
        limits: std::collections::BTreeMap<String, Either>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    #[allow(dead_code)]
    enum Either {
        Count(i64),
        Name(String),
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Flattening {
        /// Read through `deserialize_any` by its own visitor.
        #[serde(default)]
        json: serde_json::Value,
        /// An integer or `"auto"`, also through `deserialize_any`.
        #[serde(default)]
        hops: crate::config::ForwardedHops,
        #[serde(default)]
        note: String,
        #[serde(flatten)]
        outbound: OutboundCfg,
    }

    #[test]
    fn a_field_or_map_value_of_any_shape_is_known_and_a_stray_key_beside_it_is_not() {
        let raw = r#"
            [section]
            json = { a = [1, 2] }
            hops = "auto"
            note = "n"
            proxy = "http://squid:3128"
            prxy = "typo"

            [labels]
            team = "edge"
            owner = { name = "x" }

            [limits]
            burst = 3
            tier = "gold"
        "#;
        let found: Vec<String> = unknown_keys_as::<Shapes>(raw)
            .expect("replays")
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            found,
            ["unknown key section.prxy (did you mean section.proxy?)"]
        );
    }

    #[test]
    fn a_suggestion_costs_one_read_and_the_search_is_bounded_across_keys() {
        let ship = vec![Seg::Key("log".into()), Seg::Key("ship".into())];
        let table = |raw: &str| Value::Table(raw.parse::<toml::Table>().unwrap());
        let mut replays = SUGGESTION_REPLAYS;

        // A typo, and a key nothing is near: one read each.
        let root = table("[log.ship]\nbtch = 5\nqxzjvwkqxzjvwk = 1\n");
        let found = known_neighbour::<Config>(&root, &ship, "btch", &mut replays);
        assert_eq!(found.as_deref(), Some("batch"));
        let none = known_neighbour::<Config>(&root, &ship, "qxzjvwkqxzjvwk", &mut replays);
        assert_eq!(none, None);
        assert_eq!(SUGGESTION_REPLAYS - replays, 2);

        // A neighbour that is a field of another type fails the read with all of them in place,
        // so each is read alone: still found, by the reads one at a time.
        let root = table("[log.ship]\nbtch = 5\nheaders_ = 1\n");
        let mut replays = SUGGESTION_REPLAYS;
        let found = known_neighbour::<Config>(&root, &ship, "headers_", &mut replays);
        assert_eq!(
            found, None,
            "headers takes a list, so 1 is no reading of it"
        );
        let spent = SUGGESTION_REPLAYS - replays;
        assert!(
            spent > 100,
            "read one at a time after the batch failed: {spent}"
        );

        // And the reads one at a time stop when the budget is spent.
        let mut left = 10;
        assert_eq!(
            known_neighbour::<Config>(&root, &ship, "headers_", &mut left),
            None
        );
        assert_eq!(left, 0);
        let mut none_left = 0;
        let root = table("[log.ship]\nbtch = 5\n");
        assert_eq!(
            known_neighbour::<Config>(&root, &ship, "btch", &mut none_left),
            None
        );
    }

    #[test]
    fn only_the_first_keys_are_searched_for_a_suggestion() {
        let mut raw = String::from("[log.ship]\n");
        for i in 0..SUGGESTION_SEARCHES + 2 {
            raw.push_str(&format!("qxzjvwk{i:02} = 1\n"));
        }
        raw.push_str("urk = \"http://c\"\n");
        let found = unknown_keys(&raw);
        assert_eq!(found.len(), SUGGESTION_SEARCHES + 3);
        // Sorted after the others, `urk` is past the cap, so its neighbour is not searched for.
        assert!(found.iter().all(|k| k.suggestion.is_none()), "{found:?}");
        assert_eq!(
            keys("[log.ship]\nurk = \"http://c\"\n"),
            ["unknown key log.ship.urk (did you mean log.ship.url?)"]
        );
    }

    #[test]
    fn a_config_the_parser_accepts_but_the_check_cannot_read_is_a_gap_not_a_clean_file() {
        // The replay hands a TOML datetime over as a string; a `Datetime` field wants it as the
        // parser's own form. `Config` has none, so this shape stands in for a future gap.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Dated {
            at: toml::value::Datetime,
        }
        assert_eq!(
            unknown_keys_as::<Dated>("at = 1979-05-27T07:32:00Z\n"),
            None
        );
        assert_eq!(
            unknown_keys_as::<Dated>("at = \"not a date\"\n"),
            Some(Vec::new())
        );
        assert_eq!(check("[server]\nport = 8080\n"), Some(Vec::new()));
    }

    #[test]
    fn outbound_fields_come_from_serde() {
        assert_eq!(
            outbound_fields(),
            ["ca_path", "client_cert_path", "client_key_path", "proxy"]
        );
    }
}
