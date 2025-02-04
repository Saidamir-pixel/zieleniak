<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Проверяем, авторизован ли пользователь
if (!isset($_SESSION['email'])) {
    header("Location: registration.php");
    exit();
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/assets/style/assortment.css">
    <title>Zieleniak - Assortment</title>
</head>
<body>
    <header class="header">
        <div class="logo">Assortment</div>
        <div class="links">
            <a id="a1" href="../index.php">Menu</a>
        </div>
    </header>

    <div class="background-container"></div>
    <div class="background"></div>

        <div class="cards-container">
            <div class="card">
                <a href="vegetables.php">
                    <img src="/assets/pictures/assortment/vegetables.jpg" alt="Vegetables">
                    <div class="card-text">Vegetables</div>
                </a>
            </div>
            <div class="card">
                <a href="fruits.php">
                    <img src="/assets/pictures/assortment/fruits.jpg" alt="Fruits">
                    <div class="card-text">Fruits</div>
                </a>
            </div>
            <div class="card">
                <a href="special.php">
                    <img src="/assets/pictures/assortment/special.jpg" alt="Special">
                    <div class="card-text">Special</div>
                </a>
            </div>
        </div>
</body>
</html>
