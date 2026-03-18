-- examples/complex.sql
-- A realistic migration with mixed risk levels.
-- Run: schema-risk analyze examples/complex.sql --verbose
-- Run: schema-risk fix examples/complex.sql --dry-run

-- LOW: safe new table
CREATE TABLE product_tags (
    id         BIGSERIAL PRIMARY KEY,
    product_id BIGINT NOT NULL,
    name       VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MEDIUM: FK without index on referencing column
ALTER TABLE product_tags
    ADD CONSTRAINT fk_product_tags_product
    FOREIGN KEY (product_id) REFERENCES products(id);

-- HIGH: non-concurrent index (blocks writes)
-- schema-risk fix examples/complex.sql  will add CONCURRENTLY here
CREATE INDEX CONCURRENTLY idx_product_tags_product_id ON product_tags(product_id);

-- HIGH: type change (full table rewrite)
ALTER TABLE products ALTER COLUMN price TYPE NUMERIC(15, 4);

-- MEDIUM: rename breaks app code
ALTER TABLE products RENAME COLUMN description TO product_description;