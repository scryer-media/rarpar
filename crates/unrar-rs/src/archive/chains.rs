//! Indexes that keep catalog upkeep linear in the size of the archive.
//!
//! [`Linker`] joins the parts of split members and services as volumes are
//! integrated. [`CatalogIndex`] answers name and service-parent lookups.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use super::{MemberEntry, ServiceEntry};

/// What the chain linker reads of a member or service record.
pub(super) trait ChainEntry {
    fn chain_name(&self) -> &str;
    fn split_before(&self) -> bool;
    fn split_after(&self) -> bool;
    fn first_volume(&self) -> Option<usize>;
    fn last_volume(&self) -> Option<usize>;
    /// The physical position the catalog sorts by.
    fn order_key(&self) -> (usize, u64);
}

macro_rules! chain_entry {
    ($type:ty) => {
        impl ChainEntry for $type {
            fn chain_name(&self) -> &str {
                &self.file_header.name
            }
            fn split_before(&self) -> bool {
                self.file_header.split_before
            }
            fn split_after(&self) -> bool {
                self.file_header.split_after
            }
            fn first_volume(&self) -> Option<usize> {
                self.segments.first().map(|segment| segment.volume_index)
            }
            fn last_volume(&self) -> Option<usize> {
                self.segments.last().map(|segment| segment.volume_index)
            }
            fn order_key(&self) -> (usize, u64) {
                self.segments
                    .iter()
                    .map(|segment| (segment.volume_index, segment.data_offset))
                    .min()
                    .unwrap_or((usize::MAX, self.file_header.data_offset))
            }
        }
    };
}

chain_entry!(MemberEntry);
chain_entry!(ServiceEntry);

/// Whether a part may continue another: an empty name matches any name.
pub(super) fn names_compatible<E: ChainEntry>(left: &E, right: &E) -> bool {
    left.chain_name().is_empty()
        || right.chain_name().is_empty()
        || left.chain_name() == right.chain_name()
}

/// The index slots one record occupies.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Slots {
    /// Last volume, for a record that continues past it.
    tail: Option<usize>,
    /// First volume, for a record that continues an earlier one.
    head: Option<usize>,
    /// A hash of the name and the first volume, for a named record with a
    /// segment. Lookups compare the names themselves; the hash only narrows
    /// the search.
    name: Option<(u64, usize)>,
}

impl Slots {
    fn of<E: ChainEntry>(entry: &E) -> Self {
        Self {
            tail: entry.split_after().then(|| entry.last_volume()).flatten(),
            head: entry.split_before().then(|| entry.first_volume()).flatten(),
            name: (!entry.chain_name().is_empty())
                .then(|| Some((name_hash(entry.chain_name()), entry.first_volume()?)))
                .flatten(),
        }
    }
}

fn name_hash(name: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::hash::DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

/// The records under one key: most keys hold one, so one needs no
/// allocation.
#[derive(Debug)]
enum Ids {
    One(usize),
    Many(Vec<usize>),
}

impl Ids {
    fn as_slice(&self) -> &[usize] {
        match self {
            Self::One(at) => std::slice::from_ref(at),
            Self::Many(ids) => ids,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [usize] {
        match self {
            Self::One(at) => std::slice::from_mut(at),
            Self::Many(ids) => ids,
        }
    }

    fn push(&mut self, at: usize) {
        match self {
            Self::One(held) => *self = Self::Many(vec![*held, at]),
            Self::Many(ids) => ids.push(at),
        }
    }

    /// Drop `at`; whether any record is left.
    fn drop_id(&mut self, at: usize) -> bool {
        match self {
            Self::One(held) => *held != at,
            Self::Many(ids) => {
                ids.retain(|held| *held != at);
                !ids.is_empty()
            }
        }
    }
}

type Keyed<K> = HashMap<K, Ids>;

fn add_id<K: std::hash::Hash + Eq>(map: &mut Keyed<K>, key: K, at: usize) {
    match map.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut held) => held.get_mut().push(at),
        std::collections::hash_map::Entry::Vacant(free) => {
            free.insert(Ids::One(at));
        }
    }
}

fn drop_id<K: std::hash::Hash + Eq>(map: &mut Keyed<K>, key: &K, at: usize) {
    if let Some(ids) = map.get_mut(key)
        && !ids.drop_id(at)
    {
        map.remove(key);
    }
}

fn ids_of<'a, K: std::hash::Hash + Eq>(map: &'a Keyed<K>, key: &K) -> &'a [usize] {
    map.get(key).map_or(&[], Ids::as_slice)
}

/// Records by the volume they continue into, the volume they continue from,
/// and their name and first volume. Each list holds record indexes in no
/// particular order.
#[derive(Debug, Default)]
struct ChainIndex {
    tails: Keyed<usize>,
    heads: Keyed<usize>,
    /// By name hash, then by first volume, so a lookup for records that
    /// begin after a volume reads only those.
    names: HashMap<u64, BTreeMap<usize, Ids>>,
}

impl ChainIndex {
    fn build<E: ChainEntry>(entries: &[E]) -> Self {
        let mut index = Self::default();
        for (at, entry) in entries.iter().enumerate() {
            index.insert(at, &Slots::of(entry));
        }
        index
    }

    fn insert(&mut self, at: usize, slots: &Slots) {
        if let Some(tail) = slots.tail {
            add_id(&mut self.tails, tail, at);
        }
        if let Some(head) = slots.head {
            add_id(&mut self.heads, head, at);
        }
        if let Some((name, first)) = slots.name {
            match self.names.entry(name).or_default().entry(first) {
                std::collections::btree_map::Entry::Occupied(mut held) => held.get_mut().push(at),
                std::collections::btree_map::Entry::Vacant(free) => {
                    free.insert(Ids::One(at));
                }
            }
        }
    }

    fn remove(&mut self, at: usize, slots: &Slots) {
        if let Some(tail) = slots.tail {
            drop_id(&mut self.tails, &tail, at);
        }
        if let Some(head) = slots.head {
            drop_id(&mut self.heads, &head, at);
        }
        if let Some((name, first)) = slots.name
            && let Some(volumes) = self.names.get_mut(&name)
        {
            if let Some(ids) = volumes.get_mut(&first)
                && !ids.drop_id(at)
            {
                volumes.remove(&first);
            }
            if volumes.is_empty() {
                self.names.remove(&name);
            }
        }
    }

    /// Renumber after the record at `removed` left the list.
    fn removed(&mut self, removed: usize) {
        let lists = self
            .tails
            .values_mut()
            .chain(self.heads.values_mut())
            .chain(self.names.values_mut().flat_map(BTreeMap::values_mut));
        for list in lists {
            for at in list.as_mut_slice() {
                if *at > removed {
                    *at -= 1;
                }
            }
        }
    }

    fn tails(&self, volume: usize) -> &[usize] {
        ids_of(&self.tails, &volume)
    }

    fn heads(&self, volume: usize) -> &[usize] {
        ids_of(&self.heads, &volume)
    }

    /// The records whose name may be `name` and that begin after `volume`;
    /// the caller compares the names.
    fn named_after(&self, name: &str, volume: usize) -> impl Iterator<Item = usize> + '_ {
        self.names
            .get(&name_hash(name))
            .zip(volume.checked_add(1))
            .into_iter()
            .flat_map(|(volumes, from)| volumes.range(from..))
            .flat_map(|(_, ids)| ids.as_slice().iter().copied())
            .inspect(|_| {
                #[cfg(test)]
                name_visits::add();
            })
    }
}

/// The order the per-integrate catalog upkeep chose records in: the order of
/// the list, as each integrate left it sorted (or unsorted) before the next.
///
/// Integrating one record used to end with a full reconcile and, when the
/// catalog keeps physical order, a sort. The linker sorts once per batch, so
/// it ranks records the way that per-record sort would have placed them:
/// before any sort, by list position; after one, by physical key, with a
/// record pushed by the current integrate last and a record whose head moved
/// in it at its key from before the move.
#[derive(Debug)]
pub(super) struct Linker {
    index: ChainIndex,
    /// Whether the catalog keeps physical order.
    sorts: bool,
    /// Whether an integrate in this batch sorted the list, as the old upkeep
    /// did at the end of every integrate that changed it.
    by_key: bool,
    /// Whether a joinable pair existed when the batch began.
    pending: bool,
    pushed: Option<usize>,
    moved: Option<(usize, (usize, u64))>,
    /// Records the current integrate changed; only they can form a new pair.
    touched: Vec<usize>,
}

type Rank = (bool, (usize, u64), usize);

impl Linker {
    pub(super) fn new<E: ChainEntry>(entries: &[E], sorts: bool) -> Self {
        #[cfg(test)]
        linker_builds::add(entries.len());
        let index = ChainIndex::build(entries);
        let mut linker = Self {
            index,
            sorts,
            by_key: false,
            pending: false,
            pushed: None,
            moved: None,
            touched: Vec::new(),
        };
        linker.pending = (0..entries.len()).any(|at| linker.has_right(entries, at));
        linker
    }

    fn rank<E: ChainEntry>(&self, entries: &[E], at: usize) -> Rank {
        if !self.by_key {
            return (false, (0, 0), at);
        }
        if self.pushed == Some(at) {
            return (true, (0, 0), at);
        }
        match self.moved {
            Some((moved, key)) if moved == at => (false, key, at),
            _ => (false, entries[at].order_key(), at),
        }
    }

    fn first<E: ChainEntry>(
        &self,
        entries: &[E],
        candidates: impl Iterator<Item = usize>,
    ) -> Option<usize> {
        candidates.min_by_key(|at| self.rank(entries, *at))
    }

    /// Start integrating one record that the catalog does not hold yet.
    pub(super) fn begin(&mut self, len: usize) {
        self.pushed = None;
        self.moved = None;
        self.touched.clear();
        if self.pending {
            self.touched.extend(0..len);
        }
    }

    /// The first record, in catalog order, that continues into `volume`.
    pub(super) fn continued_into<E: ChainEntry>(
        &self,
        entries: &[E],
        volume: usize,
        accepts: impl Fn(&E) -> bool,
    ) -> Option<usize> {
        let from = volume.checked_sub(1)?;
        let tails = self.index.tails(from).iter().copied();
        self.first(entries, tails.filter(|at| accepts(&entries[*at])))
    }

    /// The first record, in catalog order, named `name` that begins after
    /// `volume`.
    pub(super) fn named_after<E: ChainEntry>(
        &self,
        entries: &[E],
        name: &str,
        volume: usize,
    ) -> Option<usize> {
        if name.is_empty() {
            return None;
        }
        let named = self.index.named_after(name, volume);
        self.first(
            entries,
            named.filter(|at| {
                let entry = &entries[*at];
                entry.chain_name() == name
                    && entry.first_volume().is_some_and(|first| first > volume)
            }),
        )
    }

    /// Change the record at `at` through `change`, keeping the index current.
    pub(super) fn update<E: ChainEntry, R>(
        &mut self,
        entries: &mut [E],
        at: usize,
        change: impl FnOnce(&mut E) -> R,
    ) -> R {
        let before = Slots::of(&entries[at]);
        let result = change(&mut entries[at]);
        let after = Slots::of(&entries[at]);
        if before != after {
            self.index.remove(at, &before);
            self.index.insert(at, &after);
        }
        self.touched.push(at);
        result
    }

    /// Record that the head of `at` moves; call before the change.
    pub(super) fn moving<E: ChainEntry>(&mut self, entries: &[E], at: usize) {
        self.moved = Some((at, entries[at].order_key()));
    }

    pub(super) fn push<E: ChainEntry>(&mut self, entries: &mut Vec<E>, entry: E) {
        let at = entries.len();
        self.index.insert(at, &Slots::of(&entry));
        entries.push(entry);
        self.pushed = Some(at);
        self.touched.push(at);
    }

    fn has_right<E: ChainEntry>(&self, entries: &[E], left: usize) -> bool {
        self.right_of(entries, left).is_some()
    }

    fn right_candidates<'a, E: ChainEntry>(
        &'a self,
        entries: &'a [E],
        left: usize,
    ) -> impl Iterator<Item = usize> + 'a {
        let entry = &entries[left];
        let next = entry
            .split_after()
            .then(|| entry.last_volume())
            .flatten()
            .and_then(|last| last.checked_add(1));
        next.into_iter()
            .flat_map(|next| self.index.heads(next).iter().copied())
            .filter(move |right| *right != left && names_compatible(entry, &entries[*right]))
    }

    fn right_of<E: ChainEntry>(&self, entries: &[E], left: usize) -> Option<usize> {
        self.first(entries, self.right_candidates(entries, left))
    }

    /// The pair the old all-pairs reconcile merged next: the first left in
    /// catalog order that has a right, and that left's first right.
    fn next_pair<E: ChainEntry>(&self, entries: &[E]) -> Option<(usize, usize)> {
        let mut best: Option<(Rank, usize)> = None;
        let offer = |at: usize, best: &mut Option<(Rank, usize)>| {
            let rank = self.rank(entries, at);
            if best.as_ref().is_none_or(|(held, _)| rank < *held) {
                *best = Some((rank, at));
            }
        };
        for &at in &self.touched {
            let entry = &entries[at];
            if self.has_right(entries, at) {
                offer(at, &mut best);
            }
            if entry.split_before()
                && let Some(from) = entry.first_volume().and_then(|first| first.checked_sub(1))
            {
                for &left in self.index.tails(from) {
                    if left != at && names_compatible(&entries[left], entry) {
                        offer(left, &mut best);
                    }
                }
            }
        }
        let (_, left) = best?;
        Some((left, self.right_of(entries, left)?))
    }

    /// Merge every pair the changes of this integrate made joinable, as the
    /// old reconcile did, and note the sort that reconcile ended with.
    pub(super) fn relink<E: ChainEntry>(&mut self, entries: &mut Vec<E>, merge: fn(&mut E, E)) {
        while let Some((left, right)) = self.next_pair(entries) {
            debug_assert_ne!(left, right);
            self.index.remove(right, &Slots::of(&entries[right]));
            let removed = entries.remove(right);
            self.index.removed(right);
            let shift = |at: usize| if at > right { at - 1 } else { at };
            self.pushed = self.pushed.filter(|at| *at != right).map(shift);
            self.moved = self
                .moved
                .filter(|(at, _)| *at != right)
                .map(|(at, key)| (shift(at), key));
            self.touched.retain(|at| *at != right);
            for at in &mut self.touched {
                *at = shift(*at);
            }
            let left = shift(left);
            self.update(entries, left, |entry| merge(entry, removed));
        }
        self.pending = false;
        if self.sorts {
            self.by_key = true;
        }
    }

    /// Whether the batch must end with the sort its last integrate did.
    pub(super) fn sorted(&self) -> bool {
        self.by_key
    }
}

/// How many records this thread's name lookups looked at.
#[cfg(test)]
pub(super) mod name_visits {
    use std::cell::Cell;

    thread_local! {
        static VISITED: Cell<usize> = const { Cell::new(0) };
    }

    pub(in crate::archive) fn add() {
        VISITED.with(|visited| visited.set(visited.get() + 1));
    }

    pub(in crate::archive) fn take() -> usize {
        VISITED.with(|visited| visited.replace(0))
    }
}

/// How many records this thread's linkers indexed.
#[cfg(test)]
pub(super) mod linker_builds {
    use std::cell::Cell;

    thread_local! {
        static INDEXED: Cell<usize> = const { Cell::new(0) };
    }

    pub(in crate::archive) fn add(records: usize) {
        INDEXED.with(|indexed| indexed.set(indexed.get() + records));
    }

    pub(in crate::archive) fn take() -> usize {
        INDEXED.with(|indexed| indexed.replace(0))
    }
}

/// Which member each service belongs to: the member with a data segment
/// closest before the service's first segment.
#[derive(Debug)]
pub(super) struct ParentIndex {
    parents: Vec<Option<usize>>,
    /// `(member, service)` pairs, sorted.
    children: Vec<(usize, usize)>,
}

impl ParentIndex {
    fn build(members: &[MemberEntry], services: &[ServiceEntry]) -> Self {
        let mut segments: Vec<(usize, u64, usize)> = members
            .iter()
            .enumerate()
            .flat_map(|(member, entry)| {
                entry
                    .segments
                    .iter()
                    .map(move |segment| (segment.volume_index, segment.data_offset, member))
            })
            .collect();
        #[cfg(test)]
        parent_builds::add(segments.len() + services.len());
        segments.sort_unstable();
        let parents: Vec<Option<usize>> = services
            .iter()
            .map(|service| {
                let first = service.segments.first()?;
                let below = segments.partition_point(|(volume, offset, _)| {
                    (*volume, *offset) < (first.volume_index, first.data_offset)
                });
                below.checked_sub(1).map(|at| segments[at].2)
            })
            .collect();
        let mut children: Vec<(usize, usize)> = parents
            .iter()
            .enumerate()
            .filter_map(|(service, parent)| parent.map(|member| (member, service)))
            .collect();
        children.sort_unstable();
        Self { parents, children }
    }

    pub(super) fn parent(&self, service: usize) -> Option<usize> {
        self.parents.get(service).copied().flatten()
    }

    /// The services of `member`, in catalog order.
    pub(super) fn children(&self, member: usize) -> impl Iterator<Item = usize> + '_ {
        let start = self.children.partition_point(|(held, _)| *held < member);
        self.children[start..]
            .iter()
            .take_while(move |(held, _)| *held == member)
            .map(|(_, service)| *service)
    }
}

/// How many segments and services this thread's parent indexes read.
#[cfg(test)]
pub(super) mod parent_builds {
    use std::cell::Cell;

    thread_local! {
        static READ: Cell<usize> = const { Cell::new(0) };
    }

    pub(in crate::archive) fn add(records: usize) {
        READ.with(|read| read.set(read.get() + records));
    }

    pub(in crate::archive) fn take() -> usize {
        READ.with(|read| read.replace(0))
    }
}

/// Lookups over the member and service lists, each built on first use and
/// dropped by any change to either list.
#[derive(Debug, Default)]
pub(super) struct CatalogIndex {
    names: OnceLock<HashMap<String, usize>>,
    sanitized: OnceLock<HashMap<String, usize>>,
    parents: OnceLock<ParentIndex>,
}

impl CatalogIndex {
    /// The first member stored under the raw header name `name`.
    pub(super) fn member_named(&self, members: &[MemberEntry], name: &str) -> Option<usize> {
        self.names
            .get_or_init(|| first_by(members.iter().map(|member| member.file_header.name.clone())))
            .get(name)
            .copied()
    }

    /// The first member whose sanitized name is `name`.
    pub(super) fn member_sanitized(
        &self,
        members: &[MemberEntry],
        format: crate::types::ArchiveFormat,
        name: &str,
    ) -> Option<usize> {
        self.sanitized
            .get_or_init(|| {
                first_by(members.iter().map(|member| {
                    crate::path::sanitize_member_path(
                        format,
                        member.file_header.host_os,
                        &member.file_header.name,
                    )
                }))
            })
            .get(name)
            .copied()
    }

    pub(super) fn parents(
        &self,
        members: &[MemberEntry],
        services: &[ServiceEntry],
    ) -> &ParentIndex {
        self.parents
            .get_or_init(|| ParentIndex::build(members, services))
    }
}

fn first_by(names: impl Iterator<Item = String>) -> HashMap<String, usize> {
    let mut first = HashMap::new();
    for (at, name) in names.enumerate() {
        #[cfg(test)]
        name_builds::add();
        first.entry(name).or_insert(at);
    }
    first
}

/// How many member names this thread's name maps read.
#[cfg(test)]
pub(super) mod name_builds {
    use std::cell::Cell;

    thread_local! {
        static READ: Cell<usize> = const { Cell::new(0) };
    }

    pub(in crate::archive) fn add() {
        READ.with(|read| read.set(read.get() + 1));
    }

    pub(in crate::archive) fn take() -> usize {
        READ.with(|read| read.replace(0))
    }
}
