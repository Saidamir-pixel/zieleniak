<?php
session_start();

include '../control/authController.php';
order();

// Инициализация корзины, если её еще нет
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// Добавление товара в корзину (пример)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_to_cart'])) {
    $productName = $_POST['product_name'];
    $productPrice = $_POST['product_price'];
    $quantity = $_POST['quantity'];

    $_SESSION['cart'][$productName] = [
        'price' => $productPrice,
        'quantity' => $quantity
    ];
}

function getLastOrderData($email) {
    global $dbh;

    $sql = "SELECT address, postcode, phone 
            FROM carts 
            WHERE userEmail = :email 
            ORDER BY created_at DESC 
            LIMIT 1";

    $stmt = $dbh->prepare($sql);
    $stmt->bindParam(':email', $email);
    $stmt->execute();

    return $stmt->fetch(PDO::FETCH_ASSOC) ?: []; // Если данных нет, вернёт пустой массив
}

// Получаем email текущего пользователя
$email = $_SESSION['email'];
$lastOrderData = getLastOrderData($email); // Получаем последние данные

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/assets/style/cart.css">
    <title>Cart</title>
</head>
<body>
    <div class="cart-container">
            
        <button id="emptyBucket">Empty</button>
        <form id="cart-form" method="POST">
            <div id="cart-items"></div>
            <div id="total-price" style="font-weight: bold; margin-top: 20px; text-align: right;"></div>
            <!-- Поля для ввода телефона, адреса и почтового индекса -->
            <div class="form-group">
                <label for="phone">Phone Number (+48...):</label>
                <input type="hidden" id="paymentCheck" name="paymentCheck">
                <input type="hidden" id="hiddenTotalPrice" name="hiddenTotalPrice">
                <input 
                    type="text" 
                    id="phone" 
                    name="phone" 
                    placeholder="Enter your phone number" 
                     
                    pattern="^\+48\d{9}$"
                >
                <small>Format: +48 followed by 9 digits</small>
            </div>
            

            <div class="form-group" id="form-postcode">
                <label for="postcode">Post-code (00-000):</label>
                <input 
                    type="text" 
                    id="postcode" 
                    name="postcode" 
                    placeholder="Enter your post-code" 
                    maxlength="6" 
                    pattern="^\d{2}-\d{3}$"
                    required
                >
                <small>Format: 00-000</small>
            </div>
            <div class="form-group" id="form-address">
                <label class="address" for="address">Address:</label>

                <input 
                    id="address" 
                    name="address" 
                    placeholder="Enter your address"
                    required
                >
            </div>

            <div class="form-group" id="form-date">
                <label class="date" for="date">Choose the day you would like to get your purchase:</label>

                <input 
                    type = "date"
                    id="date" 
                    name="date" 
                    placeholder="Date of order"
                >
            </div>

            <div class="cart-footer">
                <button id="submit-cart" type="submit">Submit</button>
                <button id="back-cart" type="button" onclick="window.location.href='assortment.php'">Back</button>
            </div>
        </form>
    </div>
    <div class="method">
        <div class="method-group">
            <label for="self-pickup">Self Pickup</label>
            <div class="radio">
                <input type="radio" id="self-pickup" name="payment-method" value="self-pickup" required>
            </div>
        </div>
        <div class="method-group">
            <label for="courier-pay">Pay to courier</label>
            <div class="radio">
                <input type="radio" id="courier-pay" name="payment-method" value="courier-pay" required>
            </div>
            <!-- Скрытое сообщение -->
            <div id="courier-message" style="display: none; color: red; font-size: 14px; margin-top: 10px;">
                Минимум 50 PLN.
            </div>
        </div>
            
    </div>


    <script src="../assets/scripts/cart.js"></script>
    <?php 
    // Получаем последний заказ, который не является самовывозом
    $sql = "SELECT * FROM carts WHERE userEmail = :email AND address != 'Self-Pickup' ORDER BY created_at DESC LIMIT 1";
    $stmt = $dbh->prepare($sql);
    $stmt->execute([':email' => $_SESSION['email']]);
    $lastOrderData = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($lastOrderData): ?>
        <script>
            // Передаем последние данные в JavaScript, если это не самовывоз
            window.lastOrder = <?php echo json_encode($lastOrderData); ?>;
            document.addEventListener('DOMContentLoaded', () => {
                document.getElementById('address').value = lastOrder.address || '';
                document.getElementById('postcode').value = lastOrder.postcode || '';
                document.getElementById('phone').value = lastOrder.phone || '';
            });
        </script>
    <?php endif; ?>

</body>
</html>


