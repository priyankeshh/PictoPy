use std::collections::HashMap;
use std::path::{PathBuf, Path};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;
mod cache_service;
mod file_service;
pub use cache_service::CacheService;
use chrono::{DateTime, Datelike, Utc};
use data_encoding::BASE64;
use serde::{Serialize, Deserialize};
use std::num::NonZeroU32;
use ring::rand::{SystemRandom, SecureRandom};
use ring::digest;
use ring::pbkdf2;
use ring::aead::{ Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
pub use file_service::FileService;
use image::{DynamicImage, GenericImageView, ImageBuffer, Rgba};
use tauri::path::BaseDirectory;
use tauri::Manager;
use std::fs;
use directories::ProjectDirs;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use uuid::Uuid;
use std::error::Error;
use std::ffi::OsStr;
use arrayref::array_ref;

const SECURE_FOLDER_NAME: &str = "secure_folder";
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const CURRENT_ENCRYPTION_VERSION: u8 = 1;
const KEY_ROTATION_INTERVAL: u64 = 30 * 24 * 60 * 60; // 30 days in seconds

#[derive(Serialize, Deserialize)]
pub struct EncryptedMetadata {
    pub content_type: String,
    pub original_name: String,
}

impl EncryptedMetadata {
    pub fn new(content_type: String, original_name: String) -> Self {
        Self {
            content_type,
            original_name,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SecureMedia {
    pub id: String,
    pub url: String,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryImage {
    path: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    created_at: DateTime<Utc>,
}

#[tauri::command]
pub fn get_folders_with_images(
    directory: &str,
    file_service: State<'_, FileService>,
    cache_service: State<'_, CacheService>,
) -> Vec<PathBuf> {
    if let Some(cached_folders) = cache_service.get_cached_folders() {
        return cached_folders;
    }

    let folders = file_service.get_folders_with_images(directory);
    let _ = cache_service.cache_folders(&folders);
    folders
}

#[tauri::command]
pub fn get_images_in_folder(
    folder_path: &str,
    file_service: State<'_, FileService>,
) -> Vec<PathBuf> {
    file_service.get_images_in_folder(folder_path)
}

#[tauri::command]
pub fn get_all_images_with_cache(
    state: tauri::State<FileService>,
    cache_state: tauri::State<CacheService>,
    directories: Vec<String>,
) -> Result<HashMap<u32, HashMap<u32, Vec<String>>>, String> {
    let cached_images = cache_state.get_cached_images();

    let mut images_by_year_month = if let Some(cached) = cached_images {
        let mut map: HashMap<u32, HashMap<u32, Vec<String>>> = HashMap::new();
        for path in cached {
            if let Ok(metadata) = std::fs::metadata(&path) {
                let date = metadata
                    .created()
                    .or_else(|_| metadata.modified())
                    .unwrap_or_else(|_| SystemTime::now());

                let datetime: DateTime<Utc> = date.into();
                let year = datetime.year() as u32;
                let month = datetime.month();
                map.entry(year)
                    .or_insert_with(HashMap::new)
                    .entry(month)
                    .or_insert_with(Vec::new)
                    .push(path.to_str().unwrap_or_default().to_string());
            }
        }
        map
    } else {
        let mut map: HashMap<u32, HashMap<u32, Vec<String>>> = HashMap::new();
        let mut all_image_paths: Vec<PathBuf> = Vec::new();

        for directory in directories {
            let all_images = state.get_all_images(&directory);

            for path in all_images {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    let date = metadata
                        .created()
                        .or_else(|_| metadata.modified())
                        .unwrap_or_else(|_| SystemTime::now());

                    let datetime: DateTime<Utc> = date.into();
                    let year = datetime.year() as u32;
                    let month = datetime.month();
                    map.entry(year)
                        .or_insert_with(HashMap::new)
                        .entry(month)
                        .or_insert_with(Vec::new)
                        .push(path.to_str().unwrap_or_default().to_string());

                    all_image_paths.push(path); // Collect all paths for caching
                }
            }
        }

        // Cache the flattened list of image paths
        if let Err(e) = cache_state.cache_images(&all_image_paths) {
            eprintln!("Failed to cache images: {}", e);
        }

        map
    };

    // Sort the images within each month
    for year_map in images_by_year_month.values_mut() {
        for month_vec in year_map.values_mut() {
            month_vec.sort();
        }
    }

    Ok(images_by_year_month)
}

#[tauri::command]
pub fn get_all_videos_with_cache(
    state: tauri::State<FileService>,
    cache_state: tauri::State<CacheService>,
    directories: Vec<String>, // Updated to take an array of directories
) -> Result<HashMap<u32, HashMap<u32, Vec<String>>>, String> {
    let cached_videos = cache_state.get_cached_videos();

    let mut videos_by_year_month: HashMap<u32, HashMap<u32, Vec<String>>> =
        if let Some(cached) = cached_videos {
            let mut map: HashMap<u32, HashMap<u32, Vec<String>>> = HashMap::new();
            for path in cached {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(created) = metadata.created() {
                        let datetime: DateTime<Utc> = created.into();
                        let year = datetime.year() as u32;
                        let month = datetime.month();
                        map.entry(year)
                            .or_insert_with(HashMap::new)
                            .entry(month)
                            .or_insert_with(Vec::new)
                            .push(path.to_str().unwrap_or_default().to_string());
                    }
                }
            }
            map
        } else {
            let mut map: HashMap<u32, HashMap<u32, Vec<String>>> = HashMap::new();
            for directory in directories {
                let all_videos = state.get_all_videos(&directory);
                for path in all_videos {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if let Ok(created) = metadata.created() {
                            let datetime: DateTime<Utc> = created.into();
                            let year = datetime.year() as u32;
                            let month = datetime.month();
                            map.entry(year)
                                .or_insert_with(HashMap::new)
                                .entry(month)
                                .or_insert_with(Vec::new)
                                .push(path.to_str().unwrap_or_default().to_string());
                        }
                    }
                }
            }

            // Cache the aggregated video paths
            let flattened: Vec<PathBuf> = map
                .values()
                .flat_map(|year_map| year_map.values())
                .flatten()
                .map(|s| PathBuf::from(s))
                .collect();
            if let Err(e) = cache_state.cache_videos(&flattened) {
                eprintln!("Failed to cache videos: {}", e);
            }

            map
        };

    // Sort the videos within each month
    for year_map in videos_by_year_month.values_mut() {
        for month_vec in year_map.values_mut() {
            month_vec.sort();
        }
    }

    Ok(videos_by_year_month)
}

#[tauri::command]
pub async fn share_file(path: String) -> Result<(), String> {
    use std::process::Command;

    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .args(["/select,", &path])
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .args(["-R", &path])
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(&path)
            .spawn()
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

#[tauri::command]
pub async fn save_edited_image(
    image_data: Vec<u8>,
    original_path: String,
    filter: String,
    brightness: i32,
    contrast: i32,
) -> Result<(), String> {
    let mut img = image::load_from_memory(&image_data).map_err(|e| e.to_string())?;

    // Apply filter
    match filter.as_str() {
        "grayscale(100%)" => img = img.grayscale(),
        "sepia(100%)" => img = apply_sepia(&img),
        "invert(100%)" => img.invert(),
        _ => {}
    }

    // Apply brightness and contrast
    img = adjust_brightness_contrast(&img, brightness, contrast);

    // Save the edited image
    let path = PathBuf::from(original_path);
    let file_stem = path.file_stem().unwrap_or_default();
    let extension = path.extension().unwrap_or_default();

    let mut edited_path = path.clone();
    edited_path.set_file_name(format!(
        "{}_edited.{}",
        file_stem.to_string_lossy(),
        extension.to_string_lossy()
    ));

    img.save(&edited_path).map_err(|e| e.to_string())?;

    Ok(())
}

fn apply_sepia(img: &DynamicImage) -> DynamicImage {
    let (width, height) = img.dimensions();
    let mut sepia_img = ImageBuffer::new(width, height);

    for (x, y, pixel) in img.pixels() {
        let r = pixel[0] as f32;
        let g = pixel[1] as f32;
        let b = pixel[2] as f32;

        let sepia_r = (0.393 * r + 0.769 * g + 0.189 * b).min(255.0) as u8;
        let sepia_g = (0.349 * r + 0.686 * g + 0.168 * b).min(255.0) as u8;
        let sepia_b = (0.272 * r + 0.534 * g + 0.131 * b).min(255.0) as u8;

        sepia_img.put_pixel(x, y, Rgba([sepia_r, sepia_g, sepia_b, pixel[3]]));
    }

    DynamicImage::ImageRgba8(sepia_img)
}

fn adjust_brightness_contrast(img: &DynamicImage, brightness: i32, contrast: i32) -> DynamicImage {
    let (width, height) = img.dimensions();
    let mut adjusted_img = ImageBuffer::new(width, height);

    let brightness_factor = brightness as f32 / 100.0;
    let contrast_factor = contrast as f32 / 100.0;

    for (x, y, pixel) in img.pixels() {
        let mut new_pixel = [0; 4];
        for c in 0..3 {
            let mut color = pixel[c] as f32;
            // Apply brightness
            color += 255.0 * (brightness_factor - 1.0);
            // Apply contrast
            color = (color - 128.0) * contrast_factor + 128.0;
            new_pixel[c] = color.max(0.0).min(255.0) as u8;
        }
        new_pixel[3] = pixel[3]; // Keep original alpha

        adjusted_img.put_pixel(x, y, Rgba(new_pixel));
    }

    DynamicImage::ImageRgba8(adjusted_img)
}

fn get_secure_folder_path() -> Result<PathBuf, String> {
    let project_dirs = ProjectDirs::from("com", "AOSSIE", "Pictopy")
        .ok_or_else(|| "Failed to get project directories".to_string())?;
    let mut path = project_dirs.data_dir().to_path_buf();
    path.push(SECURE_FOLDER_NAME);
    Ok(path)
}

pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    SystemRandom::new().fill(&mut salt).unwrap();
    salt
}

#[tauri::command]
pub async fn move_to_secure_folder(path: String, password: String) -> Result<(), String> {
    let secure_folder = get_secure_folder_path()?;
    let file_name = Path::new(&path)
        .file_name()
        .ok_or("Invalid file name")?
        .to_string_lossy()
        .to_string();
    
    // Generate a random UUID for the secure filename
    let secure_name = format!("{}.enc", Uuid::new_v4());
    let dest_path = secure_folder.join(&secure_name);
    
    let content = fs::read(&path).map_err(|e| e.to_string())?;
    let encrypted = encrypt_data(&content, &password, &file_name)
        .map_err(|e| e.to_string())?;
    
    fs::write(&dest_path, encrypted).map_err(|e| e.to_string())?;
    
    // Update metadata file
    let metadata_path = secure_folder.join("metadata.json");
    let mut metadata: HashMap<String, String> = if metadata_path.exists() {
        let content = fs::read_to_string(&metadata_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        HashMap::new()
    };
    
    metadata.insert(secure_name, file_name);
    fs::write(&metadata_path, serde_json::to_string(&metadata).unwrap())
        .map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
pub async fn remove_from_secure_folder(file_name: String, password: String) -> Result<(), String> {
    let secure_folder = get_secure_folder_path()?;
    let file_path = secure_folder.join(&file_name);
    let metadata_path = secure_folder.join("metadata.json");

    // Read and decrypt the file
    let encrypted_content = fs::read(&file_path).map_err(|e| e.to_string())?;
    let decrypted_content = decrypt_data(&encrypted_content, &password).map_err(|e| e.to_string())?;

    // Get the original path
    let metadata: HashMap<String, String> = serde_json::from_str(&fs::read_to_string(&metadata_path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let original_path = metadata.get(&file_name).ok_or("Original path not found")?;

    // Write the decrypted content back to the original path
    fs::write(original_path, decrypted_content.0).map_err(|e| e.to_string())?;

    // Remove the file from the secure folder and update metadata
    fs::remove_file(&file_path).map_err(|e| e.to_string())?;
    let mut updated_metadata = metadata;
    updated_metadata.remove(&file_name);
    fs::write(&metadata_path, serde_json::to_string(&updated_metadata).unwrap()).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn create_secure_folder(password: String) -> Result<(), String> {
    let secure_folder = get_secure_folder_path()?;
    fs::create_dir_all(&secure_folder).map_err(|e| e.to_string())?;
    
    let salt = generate_salt();
    let hashed_password = hash_password(&password, &salt);
    
    let config = SecureConfig {
        salt: BASE64.encode(&salt),
        hashed_password: BASE64.encode(&hashed_password),
        encryption_version: CURRENT_ENCRYPTION_VERSION,
        last_key_rotation: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    };
    
    let config_path = secure_folder.join("config.json");
    fs::write(config_path, serde_json::to_string(&config).unwrap())
        .map_err(|e| e.to_string())?;
    
    let nomedia_path = secure_folder.join(".nomedia");
    fs::write(nomedia_path, "").map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
pub async fn get_secure_media(password: String) -> Result<Vec<SecureMedia>, String> {
    let secure_folder = get_secure_folder_path()?;
    let mut secure_media = Vec::new();

    for entry in fs::read_dir(secure_folder).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();

        if path.is_file() && path.extension().map_or(false, |ext| ext == "jpg" || ext == "png") {
            let content = fs::read(&path).map_err(|e| e.to_string())?;
            let decrypted = decrypt_data(&content, &password).map_err(|e| e.to_string())?;

            let temp_dir = std::env::temp_dir();
            let temp_file = temp_dir.join(path.file_name().unwrap());
            fs::write(&temp_file, decrypted.0).map_err(|e| e.to_string())?;
            println!("SecureMedia: {:?}", path.to_string_lossy().to_string());
            println!("SecureMedia: {:?}", temp_file.to_string_lossy().to_string());
            
            secure_media.push(SecureMedia {
                id: path.file_name().unwrap().to_string_lossy().to_string(),
                url: format!("file://{}" , temp_file.to_string_lossy().to_string()),
                path: path.to_string_lossy().to_string(),
            });
        }
    }

    println!("SECURE MEDIA: {:?}" , secure_media.len());

    Ok(secure_media)
}

pub fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut hash = [0u8; digest::SHA256_OUTPUT_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        salt,
        password.as_bytes(),
        &mut hash, 
    );
    hash.to_vec()
}

pub fn encrypt_data(data: &[u8], password: &str, original_name: &str) -> Result<Vec<u8>, String> {
    let salt = generate_salt();
    let key = derive_key(password, &salt);
    
    let metadata = EncryptedMetadata::new(
        "image/jpeg".to_string(),
        original_name.to_string(),
    );
    
    let metadata_bytes = serde_json::to_vec(&metadata)
        .map_err(|e| format!("Failed to serialize metadata: {}", e))?;
    
    let nonce = generate_nonce();
    let mut encrypted = Vec::new();
    encrypted.extend_from_slice(&salt);
    encrypted.extend_from_slice(&nonce);
    
    let mut metadata_to_encrypt = metadata_bytes.clone();
    let _metadata_tag = key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut metadata_to_encrypt,
    ).map_err(|e| format!("Encryption error: {}", e))?;
    
    encrypted.extend_from_slice(&(metadata_to_encrypt.len() as u32).to_le_bytes());
    encrypted.extend_from_slice(&metadata_to_encrypt);
    
    let mut content_to_encrypt = data.to_vec();
    let _content_tag = key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut content_to_encrypt,
    ).map_err(|e| format!("Encryption error: {}", e))?;
    
    encrypted.extend_from_slice(&content_to_encrypt);
    Ok(encrypted)
}

pub fn decrypt_data(encrypted: &[u8], password: &str) -> Result<(Vec<u8>, EncryptedMetadata), String> {
    if encrypted.len() < SALT_LENGTH + NONCE_LENGTH + 4 {
        return Err("Invalid encrypted data".into());
    }
    
    let salt = array_ref!(encrypted, 0, SALT_LENGTH);
    let nonce = array_ref!(encrypted, SALT_LENGTH, NONCE_LENGTH);
    let metadata_len_bytes = array_ref!(encrypted, SALT_LENGTH + NONCE_LENGTH, 4);
    let metadata_len = u32::from_be_bytes(*metadata_len_bytes) as usize;
    
    let key = derive_key(password, salt);
    let metadata_start = SALT_LENGTH + NONCE_LENGTH + 4;
    let metadata_end = metadata_start + metadata_len;
    let mut encrypted_metadata = encrypted[metadata_start..metadata_end].to_vec();
    
    let metadata_bytes = key.open_in_place(
        Nonce::assume_unique_for_key(*nonce),
        Aad::empty(),
        &mut encrypted_metadata,
    ).map_err(|e| format!("Decryption error: {}", e))?;
    
    let metadata: EncryptedMetadata = serde_json::from_slice(metadata_bytes)?;
    
    let mut encrypted_content = encrypted[metadata_end..].to_vec();
    let content = key.open_in_place(
        Nonce::assume_unique_for_key(*nonce),
        Aad::empty(),
        &mut encrypted_content,
    ).map_err(|e| format!("Decryption error: {}", e))?;
    
    Ok((content.to_vec(), metadata))
}

#[tauri::command]
pub async fn unlock_secure_folder(password: String) -> Result<bool, String> {
    let secure_folder = get_secure_folder_path()?;
    let config_path = secure_folder.join("config.json");

    if (!config_path.exists()) {
        return Err("Secure folder not set up".to_string());
    }

    let config: serde_json::Value = serde_json::from_str(&fs::read_to_string(config_path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;

    let salt = BASE64.decode(config["salt"].as_str().ok_or("Invalid salt")?.as_bytes()).map_err(|e| e.to_string())?;
    let stored_hash = BASE64.decode(config["hashed_password"].as_str().ok_or("Invalid hash")?.as_bytes()).map_err(|e| e.to_string())?;

    let input_hash = hash_password(&password, &salt);

    Ok(input_hash == stored_hash)
}

fn derive_key(password: &str, salt: &[u8]) -> LessSafeKey {
    let mut key_bytes = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        salt,
        password.as_bytes(),
        &mut key_bytes,
    );
    
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    LessSafeKey::new(unbound_key)
}

#[tauri::command]
pub async fn check_secure_folder_status() -> Result<bool, String> {
    let secure_folder = get_secure_folder_path()?;
    let config_path = secure_folder.join("config.json");

    if !config_path.exists() {
        return Ok(false);
    }

    let config: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&config_path).map_err(|e| e.to_string())?
    ).map_err(|e| e.to_string())?;

    Ok(true)
}

fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    SystemRandom::new().fill(&mut nonce).unwrap();
    nonce
}

#[tauri::command]
pub fn get_random_memories(directories: Vec<String>, count: usize) -> Result<Vec<MemoryImage>, String> {
    let mut all_images = Vec::new();
    let mut used_paths = HashSet::new();

    for dir in directories {
        let images = get_images_from_directory(&dir)?;
        all_images.extend(images);
    }

    let mut rng = rand::thread_rng();
    all_images.shuffle(&mut rng);

    let selected_images = all_images
        .into_iter()
        .filter(|img| used_paths.insert(img.path.clone()))
        .take(count)
        .collect();

    Ok(selected_images)
}

fn get_images_from_directory(dir: &str) -> Result<Vec<MemoryImage>, String> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return Err(format!("{} is not a directory", dir));
    }

    let mut images = Vec::new();

    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();

        if path.is_dir() {
            // Recursively call get_images_from_directory for subdirectories
            let sub_images = get_images_from_directory(path.to_str().unwrap())?;
            images.extend(sub_images);
        } else if path.is_file() && is_image_file(&path) {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if let Ok(created) = metadata.created() {
                    let created_at: DateTime<Utc> = created.into();
                    images.push(MemoryImage {
                        path: path.to_string_lossy().into_owned(),
                        created_at,
                    });
                }
            }
        }
    }

    Ok(images)
}

pub fn is_image_file(path: &Path) -> bool {
    let extensions = ["jpg", "jpeg", "png", "gif"];
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| extensions.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

#[tauri::command]
pub fn delete_cache(cache_service: State<'_, CacheService>) -> bool {
    cache_service.delete_all_caches()
}

#[tauri::command]
pub fn get_server_path(handle: tauri::AppHandle) -> Result<String, String> {
    let resource_path = handle
        .path()
        .resolve("resources/server", BaseDirectory::Resource)
        .map_err(|e| e.to_string())?;
    Ok(resource_path.to_string_lossy().to_string())
}

pub fn guess_content_type(filename: &str) -> String {
    match Path::new(filename).extension().and_then(OsStr::to_str) {
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("png") => "image/png".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_encryption_decryption() {
        let test_data = b"Hello, World!";
        let password = "test_password";
        let original_name = "test.jpg";

        let encrypted = encrypt_data(test_data, password, original_name).unwrap();
        let (decrypted, metadata) = decrypt_data(&encrypted, password).unwrap();

        assert_eq!(decrypted, test_data);
        assert_eq!(metadata.original_name, original_name);
        assert_eq!(metadata.content_type, "image/jpeg");
    }

    #[test]
    fn test_secure_folder_operations() {
        let password = "test_password";
        
        // Create secure folder
        assert!(create_secure_folder(password.to_string()).is_ok());
        
        // Check status
        assert!(check_secure_folder_status().unwrap());
        
        // Verify unlock
        assert!(unlock_secure_folder(password.to_string()).unwrap());
    }
}
