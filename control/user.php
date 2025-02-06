<?php 
require_once 'telegram.php'; // Подключение функции отправки сообщений в Telegram

function user_login() {
    if (isset($_POST['password'], $_POST['email'])) {
        global $dbh;

        $email = htmlspecialchars(trim($_POST['email']));
        $password = $_POST['password'];
        $rememberMe = isset($_POST['rememberMe']); // Проверяем чекбокс

        $errors = [];

        // Поиск пользователя по email
        $stmt = $dbh->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Проверяем имя и пароль
            if (password_verify($password, $user['password'])) {
                // Успешная авторизация
                $_SESSION["email"] = $user['email'];

                // Если "Запомнить меня" включено, создаем куки
                if ($rememberMe) {
                    $token = bin2hex(random_bytes(16)); // Генерация токена
                    setcookie('auth_token', $token, time() + (86400 * 30), "/"); // 30 дней

                    // Сохраняем токен в базе данных
                    $stmt = $dbh->prepare("UPDATE users SET auth_token = :token WHERE email = :email");
                    $stmt->execute(['token' => $token, 'email' => $email]);
                }

                header("Location: /index.php");
                exit();
            } else {
                $errors[] = "Incorrect username or password.";
            }
        } else {
            $errors[] = "User with this email does not exist.";
        }

        // Сохранение ошибок и возврат на страницу входа
        if (!empty($errors)) {
            $_SESSION['errors'] = $errors;
            header('Location: logIn.php');
            exit();
        }
    }
}




function user_reg() {
    if (isset($_POST['nameOfUser']) && isset($_POST['password']) && isset($_POST['email'])) {
        global $dbh;
        $nameOfUser = htmlspecialchars($_POST['nameOfUser']);
        $email = htmlspecialchars($_POST['email']);
        $password = $_POST['password'];
        $errors = [];

        // Проверяем длину имени пользователя и пароля
        if (strlen($nameOfUser) < 6 || strlen($nameOfUser) > 10) {
            $errors[] = "The username min 6 characters and max 10.";
        }
        if (strlen($password) < 6 || strlen($password) > 20) {
            $errors[] = "The password min 6 characters and max 20.";
        }
        if (strlen($email) < 7 || strlen($email) > 30) {
            $errors[] = "The gmail min 7 characters and max 30.";
        }
        $stmtUid = $dbh->prepare("SELECT * FROM users WHERE email = ?");
        $stmtUid->execute([$email]);
        if ($stmtUid->rowCount() > 0) {
            $errors[] = "This data is already taken.";
        }

        if (!preg_match('/^[a-zA-Z0-9]+$/', $password)) {
            $errors[] = "The password can only contain letters and numbers.";
        }

        // Проверяем, есть ли ошибки
        if (!empty($errors)) {
            $_SESSION['errors'] = $errors; // Сохраняем ошибки в сессии
            header('Location: registration.php');
            exit();
        }else{
            // Регистрация нового пользователя
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $sql = "INSERT INTO users (nameOfUser, email, password) VALUES (?, ?, ?)";
            $stmt = $dbh->prepare($sql);

            header('Location: logIn.php');
            exit();
        }
    }
}


function user_token() {
    if (!isset($_SESSION['nameOfUser']) && isset($_COOKIE['auth_token'])) {
        global $dbh;
        $stmt = $dbh->prepare("SELECT * FROM users WHERE auth_token = :token");
        $stmt->execute(['token' => $_COOKIE['auth_token']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
        if ($user) {
            $_SESSION["nameOfUser"] = $user['nameOfUser'];
            $_SESSION["email"] = $user['email'];
        } else {
            // Если токен неверен, удаляем куки
            setcookie('auth_token', '', time() - 3600, "/");
        }
    }
}

function user_order() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        global $dbh;

        // Проверяем, установлена ли сессия email
        if (!isset($_SESSION['email']) || empty($_SESSION['email'])) {
            die("Ошибка: Пользователь не авторизован.");
        }

        $userEmail = $_SESSION['email'];

        // Получаем имя пользователя из базы данных
        $stmt = $dbh->prepare("SELECT nameOfUser FROM users WHERE email = ?");
        $stmt->execute([$userEmail]);
        $userData = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userData) {
            die("Ошибка: Пользователь не найден в базе данных.");
        }

        $nameOfUser = $userData['nameOfUser'];

        // Проверяем, переданы ли все необходимые данные из формы
        if (isset($_POST['product_name'], $_POST['product_price'], $_POST['product_quantity'], $_POST['phone'], $_POST['address'])) {
            $productNames = $_POST['product_name'];
            $productPrices = $_POST['product_price'];
            $productQuantities = $_POST['product_quantity'];
            $phone = htmlspecialchars($_POST['phone']);
            $address = htmlspecialchars($_POST['address']);
            $postcode = htmlspecialchars($_POST['postcode'] ?? ''); // Если пусто, пусть будет пустая строка
            $totalPrice = htmlspecialchars($_POST['hiddenTotalPrice'] ?? '0.00'); // Если пусто, пусть будет 0

            // Проверка наличия поля `date` в POST-запросе
            if (isset($_POST['date']) && !empty($_POST['date'])) {
                $date = htmlspecialchars($_POST['date']);
            } else {
                // Получаем дату последнего заказа или ставим текущую
                $stmt = $dbh->prepare("SELECT DATE(created_at) AS purchase_date FROM carts WHERE userEmail = ? ORDER BY created_at DESC LIMIT 1");
                $stmt->execute([$userEmail]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                $date = $result ? $result['purchase_date'] : date('Y-m-d');
            }

            // Определяем метод оплаты
            if ($_POST['paymentCheck'] === 'Self-Pickup') {
                $payMethod = $_POST['paymentCheck'];
                $address = "Self-Pickup";
                $postcode = "N/A";
            } elseif ($_POST['paymentCheck'] === 'Pay to courier') {
                $payMethod = $_POST['paymentCheck'];
            }

            $productsList = [];
            $orderId = uniqid();

            // Добавление заказа в базу данных
            for ($i = 0; $i < count($productNames); $i++) {
                $name = htmlspecialchars($productNames[$i]);
                $price = floatval($productPrices[$i]);
                $quantity = intval($productQuantities[$i]);

                $sql = "INSERT INTO carts (order_id, nameOfUser, userEmail, product, phone, address, postcode, date, totalPrice) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                $stmt = $dbh->prepare($sql);
                $stmt->execute([$orderId, $nameOfUser, $userEmail, "$name ($quantity x $price)", $phone, $address, $postcode, $date, $totalPrice]);

                $productsList[] = "$name - $quantity x $price PLN";
            }

            // Формирование сообщения для Telegram
            $chatId = '-1002291622952';
            $message = "Order for: $nameOfUser\nEmail: $userEmail\nPhone: $phone\nAddress: $address\nPostcode: $postcode\nTotal Price: $totalPrice PLN\nDate of the order: $date\n\nPurchases:\n" . implode("\n", $productsList);

            if (sendOrderToTelegram($message, $chatId)) {
                header("Location: profile.php");
                exit();
            }
            
        }
    }
}


function user_greenPoints() {
    try {
        $pdo = new PDO("mysql:host=localhost;dbname=zieleniak", "root", "");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Подсчёт общей суммы покупок
        $stmt = $pdo->prepare("
            SELECT SUM(totalPrice) AS total_spent
            FROM carts
            WHERE userEmail = :email
        ");
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        $totalSpent = $result['total_spent'] ?? 0; // Если NULL, устанавливаем 0
        $greenPoints = $totalSpent * 2; // Считаем Green Points

        return ['totalSpent' => $totalSpent, 'greenPoints' => $greenPoints];
    } catch (PDOException $e) {
        die("Ошибка подключения к базе данных: " . $e->getMessage());
    }
}


function update_user() {
    global $dbh; // Подключение базы данных

    $errors = [];
    $successMessage = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $newName = htmlspecialchars($_POST['newName']);
        $newPassword = $_POST['newPassword'];

        // Валидация имени пользователя
        if (strlen($newName) < 6 || strlen($newName) > 15) {
            $errors[] = "The username must be between 6 and 15 characters.";
        }

        // Валидация пароля
        if (strlen($newPassword) < 6 || strlen($newPassword) > 20 || !preg_match('/^[a-zA-Z0-9]+$/', $newPassword)) {
            $errors[] = "The password must be between 6-20 characters and only contain letters and numbers.";
        }

        if (empty($errors)) {
            // Хеширование пароля
            $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);

            // Обновление в базе данных
            $stmt = $dbh->prepare("UPDATE users SET nameOfUser = ?, password = ? WHERE email = ?");
            $stmt->execute([$newName, $newPasswordHash, $_SESSION['email']]);

            // Обновление данных сессии
            $_SESSION['nameOfUser'] = $newName;
            header("Location: profile.php");
            exit();


            // Успешное сообщение
            $_SESSION['successMessage'] = "Profile updated successfully!";
        } else {
            $_SESSION['errors'] = $errors;
        }
    }
}

?>
