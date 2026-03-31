//! Face detection and recognition data types.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions, Permissions};
use std::io::{Error, ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FACE_EMBEDDING_DIM: usize = 512;
/// File extension for bincode model files.
pub const MODEL_FILE_EXT: &str = "bin";
/// Legacy file extension for JSON model files.
pub const LEGACY_MODEL_FILE_EXT: &str = "json";

/// A detected face with bounding box, landmarks, and optional embedding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Face {
    /// Bounding box: (x1, y1, x2, y2) in pixels.
    pub bbox: [i32; 4],
    /// 5-point facial landmarks: left_eye, right_eye, nose, left_mouth, right_mouth.
    /// Stored as flat [x0,y0, x1,y1, ..., x4,y4].
    pub landmarks: [f32; 10],
    /// Detection confidence score (0.0 - 1.0).
    pub score: f32,
    /// Face embedding vector (512-dim for ArcFace). None if not yet computed.
    pub embedding: Option<Vec<f32>>,
}

impl Face {
    pub fn x1(&self) -> i32 {
        self.bbox[0]
    }
    pub fn y1(&self) -> i32 {
        self.bbox[1]
    }
    pub fn x2(&self) -> i32 {
        self.bbox[2]
    }
    pub fn y2(&self) -> i32 {
        self.bbox[3]
    }
    pub fn width(&self) -> i32 {
        self.x2() - self.x1()
    }
    pub fn height(&self) -> i32 {
        self.y2() - self.y1()
    }

    /// Get landmarks as 5 (x,y) pairs.
    pub fn landmark_points(&self) -> [(f32, f32); 5] {
        [
            (self.landmarks[0], self.landmarks[1]),
            (self.landmarks[2], self.landmarks[3]),
            (self.landmarks[4], self.landmarks[5]),
            (self.landmarks[6], self.landmarks[7]),
            (self.landmarks[8], self.landmarks[9]),
        ]
    }
}

/// A stored face model for a user — one enrollment entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceModel {
    /// User-assigned label (e.g., "laptop IR", "office webcam").
    pub label: String,
    /// Unix timestamp of enrollment.
    pub created: u64,
    /// 512-dimensional face embedding.
    pub embedding: Vec<f32>,
}

/// All enrolled face models for a single user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserModels {
    /// The username this model set belongs to.
    pub username: String,
    /// List of enrolled face models.
    pub models: Vec<FaceModel>,
}

impl UserModels {
    /// Create an empty model set for a user.
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            models: Vec::new(),
        }
    }

    /// Load from disk. Tries bincode (.bin) first, falls back to legacy JSON (.json).
    pub fn load(path: &std::path::Path) -> Result<Self, std::io::Error> {
        // Try bincode first
        if path.exists() {
            let data = std::fs::read(path)?;
            if let Ok(models) = bincode::deserialize::<Self>(&data) {
                return Ok(models);
            }
            // If bincode fails, try JSON (legacy format or wrong extension)
            let contents = String::from_utf8(data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let models: Self = serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            return Ok(models);
        }

        // Try legacy JSON path (swap extension)
        let json_path = path.with_extension(LEGACY_MODEL_FILE_EXT);
        if json_path.exists() {
            let contents = std::fs::read_to_string(&json_path)?;
            let models: Self = serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            return Ok(models);
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("model file not found: {}", path.display()),
        ))
    }

    /// Save to disk using bincode format (atomic write via temp file + rename).
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        let data = bincode::serialize(self).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        let parent = path.parent().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("path has no parent directory: {}", path.display()),
            )
        })?;
        let file_name = path.file_name().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("path has no file name: {}", path.display()),
            )
        })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_path = parent.join(format!(
            ".{}.tmp.{}.{}",
            file_name.to_string_lossy(),
            std::process::id(),
            nonce
        ));

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, path)?;
        fs::set_permissions(path, Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// Get all embeddings as a flat Vec of Vec<f32>, for matching.
    pub fn embeddings(&self) -> Vec<&[f32]> {
        self.models.iter().map(|m| m.embedding.as_slice()).collect()
    }
}

fn validate_embedding(embedding: &[f32]) -> Result<(), String> {
    if embedding.len() != FACE_EMBEDDING_DIM {
        return Err(format!(
            "invalid embedding length: expected {FACE_EMBEDDING_DIM}, got {}",
            embedding.len()
        ));
    }

    if embedding.iter().any(|value| !value.is_finite()) {
        return Err("embedding contains NaN or infinite values".to_string());
    }

    Ok(())
}

/// Dot product of two 512-dimensional vectors without validation.
/// Caller must guarantee both slices are exactly FACE_EMBEDDING_DIM long
/// and contain only finite values.
#[inline(always)]
fn dot_product_512(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), FACE_EMBEDDING_DIM);
    debug_assert_eq!(b.len(), FACE_EMBEDDING_DIM);
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Cosine similarity between two normalized embedding vectors.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Result<f32, String> {
    validate_embedding(a)?;
    validate_embedding(b)?;

    let score: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    if !score.is_finite() {
        return Err("cosine similarity produced a non-finite value".to_string());
    }

    Ok(score.clamp(-1.0, 1.0))
}

/// Find the best matching embedding from a set of known embeddings.
/// Returns (index, similarity_score). Index is None if no match exceeds threshold.
pub fn find_best_match(
    query: &[f32],
    known: &[&[f32]],
    threshold: f32,
) -> Result<(Option<usize>, f32), String> {
    validate_embedding(query)?;
    if !threshold.is_finite() {
        return Err("threshold must be finite".to_string());
    }

    if known.is_empty() {
        return Ok((None, 0.0));
    }

    let mut best_idx = 0;
    let mut best_score: f32 = f32::NEG_INFINITY;

    for (i, known_emb) in known.iter().enumerate() {
        let score = cosine_similarity(query, known_emb)?;
        if score > best_score {
            best_score = score;
            best_idx = i;
        }
    }

    if best_score >= threshold {
        Ok((Some(best_idx), best_score))
    } else {
        Ok((None, best_score))
    }
}

/// Find the best matching embedding from a flat contiguous buffer of known embeddings.
///
/// `flat_known` is a contiguous buffer of `num_known * FACE_EMBEDDING_DIM` floats.
/// All embeddings (query and known) must be pre-validated and L2-normalized.
/// This skips per-comparison validation for maximum throughput.
pub fn find_best_match_flat(
    query: &[f32],
    flat_known: &[f32],
    num_known: usize,
    threshold: f32,
) -> (Option<usize>, f32) {
    debug_assert_eq!(query.len(), FACE_EMBEDDING_DIM);
    debug_assert_eq!(flat_known.len(), num_known * FACE_EMBEDDING_DIM);

    if num_known == 0 {
        return (None, 0.0);
    }

    let mut best_idx = 0usize;
    let mut best_score = f32::NEG_INFINITY;

    for i in 0..num_known {
        let offset = i * FACE_EMBEDDING_DIM;
        let known = &flat_known[offset..offset + FACE_EMBEDDING_DIM];
        let score = dot_product_512(query, known);
        if score > best_score {
            best_score = score;
            best_idx = i;
        }
    }

    if best_score >= threshold {
        (Some(best_idx), best_score)
    } else {
        (None, best_score)
    }
}
