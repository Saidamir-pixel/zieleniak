<?php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['email'])) {
    header("Location: registration.php");
    exit();
}

require_once '../models/fruitsList.php';
require_once '../control/db.php';
include '../control/authController.php';

// Проверяем статус заказов
$settingsFile = __DIR__ . '/settings.json';
$ordersEnabled = true;

// Если файл настроек существует, читаем его
if (file_exists($settingsFile)) {
    $settings = json_decode(file_get_contents($settingsFile), true);
    $ordersEnabled = $settings['orders_enabled'];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../assets/style/product.css">
    <title>Zieleniak - Fruits</title>
</head>
<body>
    <div class="parallax-container">
        <header class="header">
            <div class="logo"><?= htmlspecialchars($_SESSION['nameOfUser']) ?></div>
            <div class="links">
                <a id="a1" href="assortment.php">Back</a>
                <a id="a1" href="vegetables.php">Vegetables</a>
            </div>
        </header>

        <div class="parallax-bg"></div>

        <div class="card-container">
            <form action="" method="post"></form>
            <?php foreach ($products as $product): ?>
                <div class="card" data-name="<?= htmlspecialchars($product['name']) ?>" data-price="<?= htmlspecialchars($product['price']) ?>">
                    <img src="<?= htmlspecialchars($product['image']) ?>" alt="<?= htmlspecialchars($product['name']) ?>">
                    <div class="card-content">
                        <h3><?= htmlspecialchars($product['name']) ?></h3>
                        <p>PLN <?= htmlspecialchars($product['price']) ?></p>
                        <div class="card-actions">
                            <button onclick="changeQuantity(event, -1)">-</button>
                            <span>0</span>
                            <button onclick="changeQuantity(event, 1)">+</button>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <?php if ($ordersEnabled): ?>
            <!-- Если заказы разрешены, показываем кнопку -->
            <button class="checkout-button" onclick="goToCart()">View Cart</button>
        <?php else: ?>
            <!-- Если заказы отключены, показываем сообщение -->
            <div class="orders-disabled" style="text-align: center; color: red; font-size: 20px; margin-top: 20px;">
                Przepraszamy, zamówienia są tymczasowo niedostępne.
            </div>
        <?php endif; ?>

    <script src="../assets/scripts/script.js"></script>
    <script src="../assets/scripts/product.js"></script>
    
</body>
</html>
