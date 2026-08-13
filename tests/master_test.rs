#[cfg(test)]
mod tests {
    use std::fs;
    use zenth_database_local::db::DbError;
    use zenth_database_local::db::MasterDb;

    fn setup_test_db() -> MasterDb {
        let _ = fs::remove_file(MasterDb::db_path());
        MasterDb::open().unwrap()
    }

    #[test]
    fn test_register_and_get_user() {
        let db = setup_test_db();

        let entry = db.register_user("alice").unwrap();
        assert_eq!(entry.salt.len(), 32);

        let retrieved = db.get_user("alice").unwrap();
        assert_eq!(entry.name_hash, retrieved.name_hash);
        assert_eq!(entry.salt, retrieved.salt);
    }

    #[test]
    fn test_duplicate_user() {
        let db = setup_test_db();

        db.register_user("bob").unwrap();
        let result = db.register_user("bob");

        assert!(matches!(result, Err(DbError::UserAlreadyExists(_))));
    }

    #[test]
    fn test_user_exists() {
        let db = setup_test_db();

        assert!(!db.user_exists_by_name("charlie").unwrap());
        db.register_user("charlie").unwrap();
        assert!(db.user_exists_by_name("charlie").unwrap());
    }
}
