<?php
session_start();
include '../control/authController.php';
login();
token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-aFq/bzH65dt+w6FI2ooMVUpc+21e0SRygnTpmBvdBgSdnuTN7QbdgL+OapgHtvPp" crossorigin="anonymous">
    <link rel="stylesheet" href="/assets/style/loginScreen.css">
</head>
<body>
    <div class="message-container">
        
    <?php if (!empty($_SESSION['errors'])): ?>
        <div class="alert alert-danger">
            <?= implode('<br>', $_SESSION['errors']); ?>
        </div>
        <?php unset($_SESSION['errors']); // Удаляем ошибки после их отображения ?>
    <?php endif; ?>

    </div>

    <div class="login-container">
        <div class="login-content">
            <h2>Authorization</h2>
            <form action="" method="post">
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>

                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <div class="tokenCheckBox">
                    <label for="rememberMe">Remember me</label>
                    <input type="checkbox" id="rememberMe" name="rememberMe">
                </div>


                <div class="buttons">
                    <button type="submit" class="button-49">Log In</button>
                    <button type="button" class="button-49"><a href="registration.php">Sign In</a></button>
                </div>
            </form>
        </div>
    </div>

</body>
</html>
