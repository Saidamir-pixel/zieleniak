<?php
// Проверка, авторизован ли пользователь
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['email'])) {
    header("Location: registration.php");
    exit();
}

unset($_SESSION['product_name']);
unset($_SESSION['product_price']);
unset($_SESSION['product_quantity']);

// Подключение к базе данных
try {
    $pdo = new PDO("mysql:host=localhost;dbname=zieleniak", "root", "");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // SQL-запрос для получения покупок пользователя, сгруппированных по уникальному идентификатору заказа
    $stmt = $pdo->prepare("
        SELECT 
            c.order_id,
            c.created_at AS purchase_date,
            GROUP_CONCAT(c.product SEPARATOR ', ') AS products,
            c.nameOfUser,
            c.userEmail,
            c.phone,
            c.address,
            c.postcode
        FROM carts c
        WHERE c.userEmail = :email
        GROUP BY c.order_id, c.created_at, c.nameOfUser, c.userEmail, c.phone, c.address, c.postcode
        ORDER BY c.created_at DESC
    ");

    $stmt->bindParam(':email', $_SESSION['email']);
    $stmt->execute();
    $carts = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    die("Ошибка подключения к базе данных: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../assets/style/profile.css">
    <title><?= htmlspecialchars($_SESSION['nameOfUser']) ?> — Profile</title>
    <script>
        function emptyBucket(event) {
            // Очистка корзины. Предположим, что корзина хранится в сессии как cart
            sessionStorage.removeItem('cart'); // или localStorage, если используется
            // Здесь может быть еще код для обновления отображения корзины в UI
            alert('Your cart has been emptied!');
        }
    </script>
</head>
<body>
    <div class="parallax-container">    
        <header class="header">
            <div class="logo"><?= htmlspecialchars($_SESSION['nameOfUser']) ?></div>
            <div class="links">
                <a id="a1" href="../index.php">Back</a>
                <a id="a2" href="../models/logout.php">Exit</a>
                <a id="a3" href="updateProfile.php">Personal Data</a>
            </div>
            <div class="burger-menu">
                <div></div>
                <div></div>
                <div></div>
            </div>
        </header>

        <div class="body-content">
            <div class="main-content">
                <div class="user-progress">
                    <h2>Your Purchases</h2>

                    <?php if (empty($carts)): ?>
                        <p>You have no purchases yet.</p>
                    <?php else: ?>
                        <?php foreach ($carts as $cart): ?>
                            <div class="cart-item">
                                <div class="date">
                                    <strong>Purchase Date:</strong> <?= htmlspecialchars($cart['purchase_date']); ?>
                                </div>
                                <div class="details">
                                    <p><strong>Products:</strong> <?= htmlspecialchars($cart['products']); ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="../assets/scripts/script.js"></script>
    <script src="../assets/scripts/cart.js"></script>
</body>
</html>
