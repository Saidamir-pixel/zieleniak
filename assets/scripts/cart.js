document.addEventListener('DOMContentLoaded', function () {
    const bucket = document.getElementById('emptyBucket');
    bucket.style.display = 'none';

    const form = document.getElementById('cart-form');
    const cartItemsDiv = document.getElementById('cart-items');
    const totalPriceDiv = document.getElementById('total-price');
    const hiddenTotalPrice = document.getElementById('hiddenTotalPrice');

    const addressForm = document.getElementById('form-address');
    const postcodeForm = document.getElementById('form-postcode');
    const postcodeInput = document.getElementById('postcode');
    const phoneInput = document.getElementById('phone');
    const selfPickupRadio = document.getElementById('self-pickup');
    const courierPayRadio = document.getElementById('courier-pay');
    const paymentCheck = document.getElementById('paymentCheck');
    const courierMessage = document.getElementById('courier-message');

    // Загружаем корзину из localStorage
    const cart = JSON.parse(localStorage.getItem('cart')) || {};

    let totalPrice = 0;

    // Если корзина пуста, скрываем кнопку очистки
    if (Object.keys(cart).length === 0) {
        bucket.style.display = 'none';
    } else {
        bucket.style.display = 'block';
    }

    // Отображение товаров в корзине
    for (const [name, { price, quantity }] of Object.entries(cart)) {
        const itemDiv = document.createElement('div');
        itemDiv.className = 'cart-item';

        itemDiv.innerHTML = `
            <input type="hidden" name="product_name[]" value="${name}">
            <input type="hidden" name="product_price[]" value="${price}">
            <input type="hidden" name="product_quantity[]" value="${quantity}">
            <p>${name} - ${quantity} x PLN ${price}</p>
        `;
        cartItemsDiv.appendChild(itemDiv);

        totalPrice += price * quantity;
    }

    totalPriceDiv.textContent = `Total: PLN ${totalPrice.toFixed(2)}`;
    hiddenTotalPrice.value = totalPrice;

    // Функция переключения полей формы
    function toggleFields() {
        if (selfPickupRadio.checked) {
            // Если выбран самовывоз
            addressForm.style.display = 'none';
            postcodeForm.style.display = 'none';
            paymentCheck.value = 'Self-Pickup';

            // Записываем статичные значения
            postcodeInput.value = '00-000';
            phoneInput.value = phoneInput.value || '+48XXXXXXXXX'; // Заглушка, если пустое
            addressForm.querySelector('input').value = 'Self-Pickup';
        } else if (courierPayRadio.checked) {
            // Если выбран курьер
            addressForm.style.display = 'block';
            postcodeForm.style.display = 'block';
            paymentCheck.value = 'Pay to courier';

            // Очищаем только в случае явного выбора курьера
            postcodeInput.value = '';
            addressForm.querySelector('input').value = '';
        }
    }

    // Назначение обработчиков событий
    if (selfPickupRadio && courierPayRadio) {
        selfPickupRadio.addEventListener('change', toggleFields);
        courierPayRadio.addEventListener('change', toggleFields);
        toggleFields(); // Инициализация состояния формы
    }

    // Автоматическое добавление тире в поле postcode
    if (postcodeInput) {
        postcodeInput.addEventListener('input', function () {
            let value = postcodeInput.value.replace(/[^0-9]/g, ''); // Удаляем нецифровые символы
            if (value.length > 2) {
                value = value.slice(0, 2) + '-' + value.slice(2);
            }
            if (value.length > 6) {
                value = value.slice(0, 6);
            }
            postcodeInput.value = value;
        });
    }

    // Проверка перед отправкой формы
    if (form) {
        form.addEventListener('submit', function (event) {
            // Если поля скрыты, заполняем их статичными значениями
            if (selfPickupRadio.checked) {
                postcodeInput.value = '00-000';
                addressForm.querySelector('input').value = 'Self-Pickup';
            } else if (courierPayRadio.checked && (!postcodeInput.value || !addressForm.querySelector('input').value)) {
                alert("Please fill in all required fields.");
                event.preventDefault(); // Блокируем отправку формы
            }
        });
    }
});
