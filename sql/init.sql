-- Создание таблицы пользователей
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `nameOfUser` VARCHAR(255) NOT NULL,
    `email` VARCHAR(255) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `auth_token` VARCHAR(255) DEFAULT NULL,
    `green_points` INT DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Создание таблицы заказов (корзина)
CREATE TABLE IF NOT EXISTS `carts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `order_id` VARCHAR(255) NOT NULL,
    `nameOfUser` VARCHAR(255) NOT NULL,
    `userEmail` VARCHAR(255) NOT NULL,
    `product` TEXT NOT NULL,
    `phone` VARCHAR(50),
    `address` VARCHAR(255),
    `postcode` VARCHAR(20),
    `date` DATE,
    `totalPrice` DECIMAL(10,2) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
