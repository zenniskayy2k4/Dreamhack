CREATE DATABASE book_db CHARACTER SET utf8;
CREATE USER 'user'@'localhost' IDENTIFIED BY 'passwd';
GRANT ALL PRIVILEGES ON book_db.* TO 'user'@'localhost';

USE `book_db`;

CREATE TABLE requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    book_title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL
);

INSERT INTO requests (book_title, author) values ('FLAG', 'DH{flag}');