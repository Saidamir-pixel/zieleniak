<?php
session_start();
require_once 'control/authController.php';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["timer"])) {
    header("Location: views/profile.php");
    exit();
}
?>


<!DOCTYPE html> 
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="assets/style/mainScreen.css">
    <title>Zieleniak</title>
</head>
<body>
    <div class="parallax-container">
            
        <header class="header">    
            <div class="logo">Zieleniak</div>
            <div class="links">
                <?php 
                    if (!isset($_SESSION['email'])) {
                        // Если пользователь не авторизован
                    } else {
                        echo '<a href="views/profile.php">Profile</a>';
                    }
                ?>
            </div>
        </header>
        <div class="parallax-bg"></div>
        <div class="content">
            <?php
                if (!isset($_SESSION['email'])) { ?>
                    <div class="button">
                        <a href="views/login.php" id="loginLink">
                            <button class="bubbly-button">Log In</button>
                        </a>
                    </div>
            <?php } else { ?>
                    <div class="button">
                        <a href="views/assortment.php" id="assortmentLink">
                            <button class="bubbly-button">Assortment</button>
                        </a>
                    </div>
                    <div class="button">
                        <a href="views/greenPoints.php" id="assortmentLink">
                            <button class="bubbly-button">Green Points</button>
                        </a>                
                    </div>
            <?php } ?>
        </div>
    </div>

    <script src="assets/scripts/script.js"></script>
</body>
</html>
