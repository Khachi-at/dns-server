use chrono::{DateTime, Local};
use derive_more::{Display, Error, From};
use serde_derive::{Deserialize, Serialize};
use std::{
    clone::Clone,
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::{Arc, RwLock},
};

use crate::dns::protocol::{DnsRecord, QueryType};
use chrono::*;

use super::protocol::{DnsPacket, ResultCode};

#[derive(Debug, Display, From, Error)]
pub enum CacheError {
    Io(std::io::Error),
    PoisonedLock,
}

type Result<T> = std::result::Result<T, CacheError>;

pub enum CacheState {
    PositiveCache,
    NegativeCache,
    NotCached,
}

#[derive(Clone, Eq, Debug, Serialize, Deserialize)]
pub struct RecordEntry {
    pub record: DnsRecord,
    pub timestamp: DateTime<Local>,
}

impl PartialEq<RecordEntry> for RecordEntry {
    fn eq(&self, other: &RecordEntry) -> bool {
        self.record == other.record
    }
}

impl Hash for RecordEntry {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.record.hash(state);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RecordSet {
    NoRecords {
        qtype: QueryType,
        ttl: u32,
        timestamp: DateTime<Local>,
    },
    Records {
        qtype: QueryType,
        records: HashSet<RecordEntry>,
    },
}

#[derive(Clone, Debug)]
pub struct DomainEntry {
    pub domain: String,
    pub record_types: HashMap<QueryType, RecordSet>,
    pub hits: u32,
    pub updates: u32,
}

impl DomainEntry {
    pub fn new(domain: String) -> DomainEntry {
        DomainEntry {
            domain: domain,
            record_types: HashMap::new(),
            hits: 0,
            updates: 0,
        }
    }

    pub fn store_nxdomain(&mut self, qtype: QueryType, ttl: u32) {
        self.updates += 1;
        let new_set = RecordSet::NoRecords {
            qtype: qtype,
            ttl: ttl,
            timestamp: Local::now(),
        };
        self.record_types.insert(qtype, new_set);
    }

    pub fn store_record(&mut self, rec: &DnsRecord) {
        self.updates += 1;
        let entry = RecordEntry {
            record: rec.clone(),
            timestamp: Local::now(),
        };
        if let Some(&mut RecordSet::Records {
            ref mut records, ..
        }) = self.record_types.get_mut(&rec.get_querytype())
        {
            if records.contains(&entry) {
                records.remove(&entry);
            }
            records.insert(entry);
            return;
        }
        let mut records = HashSet::new();
        records.insert(entry);

        let new_set = RecordSet::Records {
            qtype: rec.get_querytype(),
            records: records,
        };

        self.record_types.insert(rec.get_querytype(), new_set);
    }

    pub fn get_cache_state(&self, qtype: QueryType) -> CacheState {
        match self.record_types.get(&qtype) {
            Some(&RecordSet::Records { ref records, .. }) => {
                let now = Local::now();
                let mut valid_count = 0;
                for entry in records {
                    let ttl_offset = Duration::seconds(entry.record.get_ttl() as i64);
                    let expires = entry.timestamp + ttl_offset;
                    if expires < now {
                        continue;
                    }
                    if entry.record.get_querytype() == qtype {
                        valid_count += 1;
                    }
                }

                if valid_count > 0 {
                    CacheState::PositiveCache
                } else {
                    CacheState::NotCached
                }
            }
            Some(&RecordSet::NoRecords { ttl, timestamp, .. }) => {
                let now = Local::now();
                let ttl_offset = Duration::seconds(ttl as i64);
                let expires = timestamp + ttl_offset;
                if expires < now {
                    CacheState::NotCached
                } else {
                    CacheState::NegativeCache
                }
            }
            None => CacheState::NotCached,
        }
    }

    pub fn fill_queryresult(&self, qtype: QueryType, result_vec: &mut Vec<DnsRecord>) {
        let now = Local::now();
        let current_set = match self.record_types.get(&qtype) {
            Some(x) => x,
            None => return,
        };
        if let RecordSet::Records { ref records, .. } = *current_set {
            for entry in records {
                let ttl_offset = Duration::seconds(entry.record.get_ttl() as i64);
                let expires = entry.timestamp + ttl_offset;
                if expires < now {
                    continue;
                }
                if entry.record.get_querytype() == qtype {
                    result_vec.push(entry.record.clone());
                }
            }
        }
    }
}

#[derive(Default)]
pub struct Cache {
    domain_entries: BTreeMap<String, Arc<DomainEntry>>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            domain_entries: BTreeMap::new(),
        }
    }

    fn get_cache_state(&mut self, qname: &str, qtype: QueryType) -> CacheState {
        match self.domain_entries.get(qname) {
            Some(x) => x.get_cache_state(qtype),
            None => CacheState::NotCached,
        }
    }

    fn fill_queryresult(
        &mut self,
        qname: &str,
        qtype: QueryType,
        result_vec: &mut Vec<DnsRecord>,
        increment_stats: bool,
    ) {
        if let Some(domain_entry) = self.domain_entries.get_mut(qname).and_then(Arc::get_mut) {
            if increment_stats {
                domain_entry.hits += 1
            }

            domain_entry.fill_queryresult(qtype, result_vec);
        }
    }

    pub fn lookup(&mut self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        match self.get_cache_state(qname, qtype) {
            CacheState::PositiveCache => {
                let mut qr = DnsPacket::new();
                self.fill_queryresult(qname, qtype, &mut qr.answers, true);
                self.fill_queryresult(qname, QueryType::NS, &mut qr.authorities, false);
                Some(qr)
            }
            CacheState::NegativeCache => {
                let mut qr = DnsPacket::new();
                qr.header.rescode = ResultCode::NXDOMAIN;
                Some(qr)
            }
            CacheState::NotCached => None,
        }
    }

    pub fn store(&mut self, records: &[DnsRecord]) {
        for rec in records {
            let domain = match rec.get_domain() {
                Some(x) => x,
                None => continue,
            };
            if let Some(ref mut rs) = self.domain_entries.get_mut(&domain).and_then(Arc::get_mut) {
                rs.store_record(rec);
                continue;
            }
            let mut rs = DomainEntry::new(domain.clone());
            rs.store_record(rec);
            self.domain_entries.insert(domain.clone(), Arc::new(rs));
        }
    }

    pub fn store_nxdomain(&mut self, qname: &str, qtype: QueryType, ttl: u32) {
        if let Some(ref mut rs) = self.domain_entries.get_mut(qname).and_then(Arc::get_mut) {
            rs.store_nxdomain(qtype, ttl);
            return;
        }
        let mut rs = DomainEntry::new(qname.to_string());
        rs.store_nxdomain(qtype, ttl);
        self.domain_entries.insert(qname.to_string(), Arc::new(rs));
    }
}

pub struct SynchronizedCache {
    pub cache: RwLock<Cache>,
}

impl SynchronizedCache {
    pub fn new() -> SynchronizedCache {
        SynchronizedCache {
            cache: RwLock::new(Cache::new()),
        }
    }

    pub fn list(&self) -> Result<Vec<Arc<DomainEntry>>> {
        let cache = self.cache.read().map_err(|_| CacheError::PoisonedLock)?;
        let mut list = Vec::new();
        for rs in cache.domain_entries.values() {
            list.push(rs.clone());
        }
        Ok(list)
    }

    pub fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let mut cache = match self.cache.write() {
            Ok(x) => x,
            Err(_) => return None,
        };
        cache.lookup(qname, qtype)
    }

    pub fn store(&self, records: &[DnsRecord]) -> Result<()> {
        let mut cache = self.cache.write().map_err(|_| CacheError::PoisonedLock)?;
        cache.store(records);
        Ok(())
    }

    pub fn store_nxdomain(&self, qname: &str, qtype: QueryType, ttl: u32) -> Result<()> {
        let mut cache = self.cache.write().map_err(|_| CacheError::PoisonedLock)?;
        cache.store_nxdomain(qname, qtype, ttl);
        Ok(())
    }
}

// TODO. UT
