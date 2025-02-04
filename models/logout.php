<?php
session_start(); // Начинаем сессию

// Подключаемся к базе данных
include '../control/authController.php';


// Если пользователь залогинен, удаляем его токен из базы данных
if (isset($_SESSION['email'])) {
    $stmt = $dbh->prepare("UPDATE users SET auth_token = NULL WHERE email = :email");
    $stmt->execute(['email' => $_SESSION['email']]);
}

// Удаляем все данные сессии
session_unset();
session_destroy();

// Удаляем куки с токеном
setcookie('auth_token', '', time() - 3600, "/");

// Перенаправляем пользователя на страницу авторизации
header('Location: /views/logIn.php');
exit;
?>

