<?php
require_once 'db.php';
require_once 'user.php';

// Функция для отправки сообщений в Telegram
function sendOrderToTelegram($message, $chatId) {
    $token = '7845380928:AAHcaQkn71lxNNdj1JRpnaqquzGdcYr3PNI'; // Токен вашего бота
    $url = "https://api.telegram.org/bot$token/sendMessage";

    // Добавляем кнопки
    $keyboard = [
        'inline_keyboard' => [
            [
                ['text' => 'Нет некоторых продуктов', 'callback_data' => 'missing_items'],
                ['text' => 'Заказ готов', 'callback_data' => 'order_ready'],
                ['text' => 'Заказ оплачен', 'callback_data' => 'order_paid']
            ]
        ]
    ];

    $data = [
        'chat_id' => $chatId,
        'text' => $message,
        'reply_markup' => json_encode($keyboard),
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);

    $response = curl_exec($ch);
    curl_close($ch);

    return $response;
}


// Получаем входящий запрос от Telegram
$request = file_get_contents('php://input');
$data = json_decode($request, true);

// Проверяем, есть ли данные callback-запроса
if (isset($data['callback_query'])) {
    $callbackData = $data['callback_query']['data']; // Получаем данные callback
    $messageId = $data['callback_query']['message']['message_id'];
    $chatId = $data['callback_query']['message']['chat']['id'];

    // Обработка callback-запросов
    if ($callbackData === 'order_paid') {
        // Извлекаем ID заказа из текста сообщения
        $orderId = extractOrderId($data['callback_query']['message']['text']); // Функция для извлечения ID заказа

        if ($orderId) {
            // Обновляем статус оплаты в базе данных
            global $dbh;
            $stmt = $dbh->prepare("UPDATE carts SET payment_confirmed = 1 WHERE order_id = :order_id");
            $stmt->execute([':order_id' => $orderId]);

            // Пересчёт GreenPoints
            $stmt = $dbh->prepare("
                SELECT SUM(totalPrice) AS total_spent
                FROM carts
                WHERE userEmail = (SELECT userEmail FROM carts WHERE order_id = :order_id)
                  AND payment_confirmed = 1
            ");
            $stmt->execute([':order_id' => $orderId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            $totalSpent = $result['total_spent'] ?? 0;
            $greenPoints = $totalSpent * 2;

            // Обновление GreenPoints пользователя
            $stmt = $dbh->prepare("UPDATE users SET green_points = :green_points WHERE email = (SELECT userEmail FROM carts WHERE order_id = :order_id)");
            $stmt->execute([':green_points' => $greenPoints, ':order_id' => $orderId]);

            sendOrderToTelegram("GreenPoints обновлены для заказа ID: $orderId. Всего GreenPoints: $greenPoints.", $chatId);
        } else {
            sendOrderToTelegram("Ошибка: не удалось извлечь ID заказа.", $chatId);
        }
    }
}

// Функция для извлечения ID заказа из текста сообщения
function extractOrderId($messageText) {
    preg_match('/Order ID: (\w+)/', $messageText, $matches);
    return $matches[1] ?? null;
}


