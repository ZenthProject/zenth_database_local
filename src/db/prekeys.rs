// src/db/prekeys.rs
use super::user::UserDb;
use super::error::DbError;

/// Une ligne à insérer dans pre_keys. `None` sur les champs signed_*/pq_* pour une OTPK simple.
pub struct PreKeyRow {
    pub pre_key_id: Option<i64>,
    pub pre_key_public: Option<Vec<u8>>,
    pub private_encrypted: Vec<u8>,
    pub private_iv: Vec<u8>,
    pub signed_id: Option<i64>,
    pub signed_public: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub pq_id: Option<i64>,
    pub pq_public: Option<Vec<u8>>,
}

impl UserDb {
    /// Insère le bundle complet à l'inscription (OTPKs + signed + 2 kyber), en une seule transaction.
    pub fn save_prekey_bundle(&self, user_id: i64, rows: &[PreKeyRow], timestamp: i64) -> Result<(), DbError> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        for row in rows {
            tx.execute(
                "INSERT INTO pre_keys (user_id, pre_key_id, pre_key_public, pre_key_private_encrypted, pre_key_iv,
                 signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature,
                 pq_pre_key_id, pq_pre_key_public, created_at, used)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0)",
                rusqlite::params![user_id, row.pre_key_id, row.pre_key_public, row.private_encrypted, row.private_iv,
                    row.signed_id, row.signed_public, row.signature, row.pq_id, row.pq_public, timestamp],
            ).map_err(DbError::from)?;
        }
        tx.commit().map_err(DbError::from)
    }

    /// Renouvellement d'OTPKs après coup (idempotent via OR IGNORE), en transaction.
    pub fn insert_otpk_batch(&self, user_id: i64, prekeys: &[(u32, Vec<u8>, Vec<u8>, Vec<u8>)], timestamp: i64) -> Result<(), DbError> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        for (pre_key_id, public_key, private_encrypted, private_iv) in prekeys {
            tx.execute(
                "INSERT OR IGNORE INTO pre_keys (user_id, pre_key_id, pre_key_public,
                 pre_key_private_encrypted, pre_key_iv, created_at, used)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                rusqlite::params![user_id, *pre_key_id as i64, public_key, private_encrypted, private_iv, timestamp],
            ).map_err(DbError::from)?;
        }
        tx.commit().map_err(DbError::from)
    }
}