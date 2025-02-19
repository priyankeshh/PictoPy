use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};

// Import the modules we want to test
use pictopy::services::*;

#[test]
fn test_guess_content_type() {
    assert_eq!(guess_content_type("test.jpg"), "image/jpeg");
    assert_eq!(guess_content_type("test.jpeg"), "image/jpeg");
    assert_eq!(guess_content_type("test.png"), "image/png");
    assert_eq!(guess_content_type("test.unknown"), "application/octet-stream");
}

#[test]
fn test_is_image_file() {
    assert!(is_image_file(Path::new("test.jpg")));
    assert!(is_image_file(Path::new("test.jpeg")));
    assert!(is_image_file(Path::new("test.png")));
    assert!(is_image_file(Path::new("test.gif")));
    assert!(!is_image_file(Path::new("test.txt")));
    assert!(!is_image_file(Path::new("test")));
}

#[test]
fn test_hash_password() {
    let password = "test123";
    let salt = generate_salt();
    
    // Same password and salt should produce same hash
    let hash1 = hash_password(password, &salt);
    let hash2 = hash_password(password, &salt);
    assert_eq!(hash1, hash2);
    
    // Different salt should produce different hash
    let different_salt = generate_salt();
    let hash3 = hash_password(password, &different_salt);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_encrypt_decrypt_data() {
    let original_data = b"Hello, World!";
    let password = "test123";
    let filename = "test.txt";

    // Test encryption
    let encrypted = encrypt_data(original_data, password, filename).unwrap();
    assert!(!encrypted.is_empty());
    
    // Test decryption
    let (decrypted, metadata) = decrypt_data(&encrypted, password).unwrap();
    assert_eq!(original_data.to_vec(), decrypted);
    assert_eq!(metadata.original_name, filename);
    assert_eq!(metadata.content_type, "application/octet-stream");
    assert_eq!(metadata.version, 1);
    
    // Verify timestamp is recent
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(metadata.timestamp <= now);
    assert!(metadata.timestamp > now - 10); // Within last 10 seconds
}

#[test]
fn test_memory_image_creation() {
    let path = "test/path/image.jpg".to_string();
    let now = DateTime::from(SystemTime::now());
    
    let memory = MemoryImage {
        path: path.clone(),
        created_at: now,
    };
    
    assert_eq!(memory.path, path);
    assert_eq!(memory.created_at.timestamp(), now.timestamp());
}

#[test]
fn test_secure_media_creation() {
    let id = "test-id".to_string();
    let url = "file:///test/path".to_string();
    let path = "/test/path".to_string();
    
    let media = SecureMedia {
        id: id.clone(),
        url: url.clone(),
        path: path.clone(),
    };
    
    assert_eq!(media.id, id);
    assert_eq!(media.url, url);
    assert_eq!(media.path, path);
}