-- login /usr/local/mysql-8.0.32-macos13-arm64/bin/mysql -u root -p


CREATE DATABASE PCS;

USE PCS;

CREATE TABLE `users` (
  `username` varchar(255) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`username`)
)

DESC USERS;

CREATE TABLE `transactions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `transaction_type` varchar(255) NOT NULL,
  `transaction_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `username` (`username`),
  CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`username`) REFERENCES `users` (`username`) ON DELETE CASCADE
)

DESC TRANSACTIONS;

CREATE TABLE `acess_control` (
  `public_key` varchar(2048) NOT NULL,
  `private_key` varchar(2048) NOT NULL,
  `username` varchar(255) NOT NULL,
  `re` tinyint(1) NOT NULL,
  `wr` tinyint(1) NOT NULL,
  `delet` tinyint(1) NOT NULL,
  `cre` tinyint(1) NOT NULL,
  `rest` tinyint(1) NOT NULL,
  KEY `username` (`username`),
  CONSTRAINT `acess_control_ibfk_1` FOREIGN KEY (`username`) REFERENCES `users` (`username`) ON DELETE CASCADE
)

DESC ACESS_CONTROL;

SHOW TABLES;

SELECT * FROM TRANSACTIONS;
SELECT * FROM USERS;
SELECT * FROM ACESS_CONTROL;


