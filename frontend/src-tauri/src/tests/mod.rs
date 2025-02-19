use crate::services::{
    guess_content_type,
    is_image_file,
    generate_salt,
    hash_password,
    encrypt_data,
    decrypt_data
};
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_encryption_decryption() {
        let original_data = b"Hello, World!";
        let password = "test123";
        let filename = "test.txt";

        let encrypted = encrypt_data(original_data, password, filename).unwrap();
        let (decrypted, metadata) = decrypt_data(&encrypted, password).unwrap();
        
        assert_eq!(original_data.to_vec(), decrypted);
        assert_eq!(metadata.content_type, "application/octet-stream");
        assert_eq!(metadata.original_name, filename);
    }

    #[test]
    fn test_password_hashing() {
        let password = "test123";
        let salt = generate_salt();
        
        let hash1 = hash_password(password, &salt);
        let hash2 = hash_password(password, &salt);
        
        assert_eq!(hash1, hash2);
        
        let different_salt = generate_salt();
        let hash3 = hash_password(password, &different_salt);
        assert_ne!(hash1, hash3);
    }
}