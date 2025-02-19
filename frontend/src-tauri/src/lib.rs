pub mod services;
pub mod repositories;
pub mod models;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub enum FileType {
    Image,
    Document,
    Other,
}

pub trait CacheRepository {
    fn store(&self, key: &str, value: &[u8]) -> Result<(), String>;
    fn retrieve(&self, key: &str) -> Option<Vec<u8>>;
    fn clear(&self) -> bool;
}

pub trait FileRepository {
    fn save(&self, path: &str, content: &[u8]) -> Result<(), String>;
    fn load(&self, path: &str) -> Result<Vec<u8>, String>;
    fn exists(&self, path: &str) -> bool;
}

