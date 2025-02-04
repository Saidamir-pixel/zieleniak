<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
include('../control/authController.php');
reg();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/assets/style/regScreen.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-aFq/bzH65dt+w6FI2ooMVUpc+21e0SRygnTpmBvdBgSdnuTN7QbdgL+OapgHtvPp" crossorigin="anonymous">
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const messages = document.querySelectorAll('.alert');
            messages.forEach(msg => {
                setTimeout(() => {
                    msg.style.display = 'none';
                }, 5000);
            });
        });
    </script>
    <title>Let's f*cking GO!</title>
</head>
<body>
    <div class="message-container">
        <?php
            if (!empty($_SESSION['errors'])) {
                foreach ($_SESSION['errors'] as $error) {
                    echo '<div class="alert alert-danger">' . $error . '</div>';
                    echo '<br>';
                }
                unset($_SESSION['errors']); // Очистка сообщений об ошибках после их отображения
            }
        ?>
    </div>  

    <div class="login-container">
        <h2>Registration</h2>
        <form id="form" action="" method="post">
            <div class="form-group">
                <label for="username">Name of user:</label>
                <input type="text" maxlength="10" id="username" name="nameOfUser" required>
            </div>

            <div class="form-group">
                <label for="email">Your gmail:</label>
                <input type="text" maxlength="30" id="email" name="email" required>
            </div>

            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>

            <div class="buttons">
                <button type="submit" class="button-49">
                    Sign In
                </button>

                <a href="logIn.php">
                    <button type="button" id="secondButton" class="button-49">
                        Back
                    </button>
                </a>
            </div>
        </form>
    </div>

<script src="../assets/scripts/warningPass.js"></script>
</body>
</html>
