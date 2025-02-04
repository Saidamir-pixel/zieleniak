<?php
// Проверка авторизации
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['email'])) {
    header("Location: registration.php");
    exit();
}

// Подключение к базе данных
try {
    $pdo = new PDO("mysql:host=localhost;dbname=zieleniak", "root", "");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Получаем текущие Green Points пользователя
    $stmt = $pdo->prepare("SELECT green_points FROM users WHERE email = :email");
    $stmt->bindParam(':email', $_SESSION['email']);
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    $greenPoints = $result['green_points'] ?? 0; // Если NULL, устанавливаем 0

} catch (PDOException $e) {
    die("Ошибка подключения к базе данных: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../assets/style/greenPoints.css">
    <title>Green Points</title>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">Zieleniak</div>
            <div class="links">
                <a href="profile.php">Profile</a>
                <a href="../index.php">Back</a>
            </div>
        </header>
        <main class="content">
            <h1>Green Points</h1>
            <p><strong>Green Points:</strong> <?= htmlspecialchars($greenPoints); ?></p>
            <p>Обменивайте свои Green Points на эксклюзивные товары!</p>
        </main>
    </div>
</body>
</html>
