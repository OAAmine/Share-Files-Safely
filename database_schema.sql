CREATE DATABASE sfs;
USE sfs;
CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    email VARCHAR(120) NOT NULL,
    two_factor_secret VARCHAR(128),
    verification_code VARCHAR(6),
    first_login BOOLEAN DEFAULT TRUE,
    last_otp_generation_time DATETIME
);

CREATE TABLE groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    expiry_date DATE
);




CREATE TABLE user_groups (
    user_id INT,
    group_id INT,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);

CREATE TABLE file (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    date_of_upload TIMESTAMP NOT NULL,
    uploaded_by INT,
    size BIGINT,
    FOREIGN KEY (uploaded_by) REFERENCES user(id)
);

CREATE TABLE file_groups (
    file_id INT,
    group_id INT,
    PRIMARY KEY (file_id, group_id),
    FOREIGN KEY (file_id) REFERENCES file(id),
    FOREIGN KEY (group_id) REFERENCES groups(id)
);

CREATE TABLE access (
    user_id INT,
    file_id INT,
    PRIMARY KEY (user_id, file_id),
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (file_id) REFERENCES file(id)
);

CREATE TABLE file_downloads (
    DownloadID INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    file_id INT,
    DownloadDate DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (file_id) REFERENCES file(id)
);



--FOR TESTING
-- INSERT INTO users (username, password_hash, email) VALUES ('user1', 'password_hash_1', 'user1@example.com');
-- INSERT INTO users (username, password_hash, email) VALUES ('user2', 'password_hash_2', 'user2@example.com');


-- --STUDY LATER MAYBE USE WWW-SFS AS USER FOR MORE SECURITY
-- GRANT ALL PRIVILEGES ON sfs.* TO 'www-sfs'@'localhost';

