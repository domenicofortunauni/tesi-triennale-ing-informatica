SET NAMES utf8mb4;

USE labtesi;

CREATE TABLE IF NOT EXISTS products (
    id    INT PRIMARY KEY,
    name  VARCHAR(128) NOT NULL,
    price DECIMAL(10,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id       INT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    password VARCHAR(64) NOT NULL,
    role     VARCHAR(32) NOT NULL
);

INSERT INTO products (id, name, price) VALUES
    (1,  'Tastiera senza fili',      29.90),
    (2,  'Tastiera meccanica',       79.00),
    (3,  'Mouse ottico',             15.50),
    (4,  'Hub USB-C',                42.00),
    (5,  'Monitor 27 pollici',      219.99),
    (6,  'Supporto per portatile',   34.90),
    (7,  'Webcam Full HD',           55.00),
    (8,  'Cuffie con microfono',    149.00),
    (9,  'Lampada da scrivania',     24.90),
    (10, 'Macchina per il caffè',    99.90);

INSERT INTO users (id, username, password, role) VALUES
    (1,  'admin',     'S3cr3t_admin_pw', 'admin'),
    (2,  'mrossi',    'password1',       'customer'),
    (3,  'gverdi',    'qwerty2024',      'customer'),
    (4,  'lbianchi',  'lulu_2019',       'customer'),
    (5,  'fgiallo',   'hunter2',         'customer'),
    (6,  'giulia',    'password123',     'customer'),
    (7,  'marco',     'hunter2',         'customer'),
    (8,  'chiara',    'qwerty2020',      'customer'),
    (9,  'luca',      'lasciamientrare', 'customer'),
    (10, 'sara',      'primavera2026',   'customer'),
    (11, 'andrea',    'cavallocorretto', 'customer'),
    (12, 'elena',     'soleluna',        'customer'),
    (13, 'paolo',     'p@ssw0rd',        'customer'),
    (14, 'davide',    'monitor99',       'customer'),
    (15, 'francesca', 'benvenuto1',      'customer');
