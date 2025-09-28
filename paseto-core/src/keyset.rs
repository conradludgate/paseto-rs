use hashbrown::HashTable;

use crate::{
    key::{Key, KeyId},
    version::{Marker, PaserkVersion},
};

/// A set of [`Key`]s, accessed via their [`KeyId`]
pub struct KeySet<V: PaserkVersion, K: Marker> {
    set: HashTable<(KeyId<V, K>, Key<V, K>)>,
}

impl<V: PaserkVersion, K: Marker> KeySet<V, K> {
    pub fn insert(&mut self, k: Key<V, K>) {
        let id = k.id();
        let hash = encode_hash(&id);
        self.set
            .entry(hash, |key| key.0 == id, |key| encode_hash(&key.0))
            .or_insert((id, k));
    }

    pub fn get(&mut self, id: KeyId<V, K>) -> Option<&Key<V, K>> {
        let hash = encode_hash(&id);
        self.set.find(hash, |key| key.0 == id).map(|key| &key.1)
    }
}

fn encode_hash<V: PaserkVersion, K: Marker>(id: &KeyId<V, K>) -> u64 {
    u64::from_ne_bytes(*id.id.first_chunk().unwrap())
}
