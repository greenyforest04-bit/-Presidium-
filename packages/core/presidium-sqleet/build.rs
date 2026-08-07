fn main() {
    cc::Build::new()
        .file("vendor/sqleet/sqleet.c")
        .define("SQLITE_THREADSAFE", "1")
        .define("SQLITE_DEFAULT_FOREIGN_KEYS", "1")
        .define("SQLITE_TEMP_STORE", "2")
        .define("SQLITE_OMIT_LOAD_EXTENSION", "1")
        .warnings(false)
        .compile("sqleet");
    println!("cargo:rerun-if-changed=vendor/sqleet/sqleet.c");
    println!("cargo:rerun-if-changed=vendor/sqleet/sqleet.h");
}
