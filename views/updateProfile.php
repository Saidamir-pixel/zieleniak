<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['email'])) {
    header("Location: registration.php");
    exit();
}
require_once '../control/authController.php';

// Проверьте авторизацию
update();

$errors = [];
$successMessage = '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Profile</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/style/updateProfile.css">
</head>
<body>
    <div class="container">
        <h2>Update Profile</h2>


        <?php if (!empty($_SESSION['errors'])): ?>
            <div class="alert alert-danger">
                <?= implode('<br>', $_SESSION['errors']); ?>
            </div>
            <?php unset($_SESSION['errors']); ?>
        <?php endif; ?>

        <?php if (!empty($_SESSION['successMessage'])): ?>
            <div class="alert alert-success">
                <?= $_SESSION['successMessage']; ?>
            </div>
            <?php unset($_SESSION['successMessage']); ?>
        <?php endif; ?>


        <form method="POST" action="">
            <div class="form-group">
                <label for="newName">New Username:</label>
                <input type="text" id="newName" name="newName" maxlength="10" required>
            </div>

            <div class="form-group">
                <label for="newPassword">New Password:</label>
                <input type="password" id="newPassword" name="newPassword" required>
            </div>
            <div class="controllers">
                <button type="submit" class="button-49">Save Changes</button>
                <button type="button" class="button-49" onclick="window.location.href='profile.php'">Back</button>
            </div>

        </form>
    </div>
</body>
</html>