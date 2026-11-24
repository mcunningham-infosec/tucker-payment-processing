-- Dog-themed (fictional) mailing addresses for the demo customers. Safe to re-run.
-- Used only as the ship-to address in Tucker's Treats; Tucker the chatbot never reads them.
ALTER TABLE demo.customers ADD COLUMN IF NOT EXISTS street TEXT;
ALTER TABLE demo.customers ADD COLUMN IF NOT EXISTS city   TEXT;
ALTER TABLE demo.customers ADD COLUMN IF NOT EXISTS state  TEXT;
UPDATE demo.customers SET street='12 Fetch Lane',            city='Barkington',     state='NJ' WHERE customer_ref='TPP-1001';
UPDATE demo.customers SET street='48 Biscuit Boulevard',     city='Pawtlanta',      state='GA' WHERE customer_ref='TPP-1002';
UPDATE demo.customers SET street='5 Squeaky Toy Court',      city='Chewcago',       state='IL' WHERE customer_ref='TPP-1003';
UPDATE demo.customers SET street='221 Tennis Ball Terrace',  city='San Furancisco', state='CA' WHERE customer_ref='TPP-1004';
UPDATE demo.customers SET street='9 Belly Rub Road',         city='Pawstin',        state='TX' WHERE customer_ref='TPP-1005';
UPDATE demo.customers SET street='1 Not the Pound Way',      city='Not the Pound',  state='NJ' WHERE customer_ref='TPP-0001';
