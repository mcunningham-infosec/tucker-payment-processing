-- Tucker's Treats - the demo store's catalog. Run after schema.sql (and again any time to reset the catalog).
-- The web page shows exactly what this table says; prices are ALWAYS taken from here at checkout,
-- never from the browser.
DROP TABLE IF EXISTS demo.products;
CREATE TABLE demo.products (
    sku          TEXT PRIMARY KEY,            -- e.g. TT-101
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL,               -- treat / toy / comfort
    price_usd    NUMERIC(8,2) NOT NULL CHECK (price_usd > 0),
    blurb        TEXT NOT NULL,
    image        TEXT NOT NULL,               -- file name under site/assets/products/
    tucker_rating INT NOT NULL CHECK (tucker_rating BETWEEN 1 AND 5),
    sort_order   INT NOT NULL
);

INSERT INTO demo.products (sku, name, kind, price_usd, blurb, image, tucker_rating, sort_order) VALUES
 ('TT-101', 'Peanut Butter Biscuits', 'treat',   8.49, 'Crunchy, oven-baked, and gone in about four seconds.',               'biscuits.svg',     5, 1),
 ('TT-102', 'Bacon Strips',           'treat',   7.49, 'Chewy strips that smell like bacon. Tucker''s weekend favorite.',      'bacon.svg',        5, 2),
 ('TT-103', 'Squeaky Credit Card',    'toy',     6.99, 'The only card Tucker is allowed to hold. Squeaks, never charges.',    'squeaky-card.svg', 4, 3),
 ('TT-104', 'Tennis Balls (3-pack)',  'toy',     5.99, 'Extra fuzzy. One for fetch, one for chewing, one for under the couch.', 'tennis-balls.svg', 5, 4),
 ('TT-105', 'Rope Tug Toy',           'toy',     9.99, 'Braided cotton rope for tug-of-war. Tucker always wins.',             'rope.svg',         4, 5),
 ('TT-106', 'Cozy Nap Pillow',        'comfort', 24.99, 'For when the spending cap kicks in and Tucker takes a nap.',          'nap-pillow.svg',   5, 6);

GRANT SELECT ON demo.products TO tucker_app;

-- Tucker himself pays for every Treats order: his card is on file, so visitors never enter or choose one.
-- (Not listed with the demo customers on the site; safe to re-run.)
INSERT INTO demo.customers (id, customer_ref, full_name, zip, email, member_since, plan)
VALUES (100, 'TPP-0001', 'Tucker (Chief Treat Officer)', '00000', 'tucker@example.com', '2019-04-01', 'Founder')
ON CONFLICT (id) DO NOTHING;
INSERT INTO demo.cards (id, customer_id, brand, last4, exp_month, exp_year, status, vault_token)
VALUES (100, 100, 'Visa', '7777', 12, 2030, 'active', 'tok_tucker_treat_fund')
ON CONFLICT (id) DO NOTHING;
