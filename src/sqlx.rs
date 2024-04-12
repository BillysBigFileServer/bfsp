use sqlx::{postgres::PgArgumentBuffer, types::Text, Postgres};

use crate::{ChunkHash, ChunkID};

impl sqlx::Type<Postgres> for ChunkID {
    fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, Postgres> for ChunkID {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        Text(self.to_string()).encode(buf)
    }
}

impl sqlx::Type<Postgres> for ChunkHash {
    fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, Postgres> for ChunkHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        Text(self.to_string()).encode(buf)
    }
}
