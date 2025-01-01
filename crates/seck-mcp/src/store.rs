use std::collections::HashMap;
use std::sync::Mutex;

pub struct ReportStore {
    inner: Mutex<HashMap<String, serde_json::Value>>,
}

impl Default for ReportStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn put(&self, v: serde_json::Value) -> String {
        let bytes = serde_json::to_vec(&v).unwrap_or_default();
        let id = hex::encode(seck_crypto::hash::sha3_256(&bytes));
        self.inner.lock().unwrap().insert(id.clone(), v);
        id
    }

    pub fn get(&self, id: &str) -> Option<serde_json::Value> {
        self.inner.lock().unwrap().get(id).cloned()
    }
}
