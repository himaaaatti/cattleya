
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED PRIMARY KEY,
    token text NOT NULL,
    secret text NOT NULL,
    name text NOT NULL
);

CREATE TABLE IF NOT EXISTS journal (
    id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNSIGNED NOT NULL,
    budget INT NOT NULL,
    type ENUM('INCOME', 'OUTGO') NOT NULL,
    date DATE NOT NULL,
    FOREIGN KEY(user_id) references users(id)
);

