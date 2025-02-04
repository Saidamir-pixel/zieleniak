const cart = JSON.parse(localStorage.getItem('cart')) || {}; // Восстановление корзины

// Изменение количества продукта
function changeQuantity(event, delta) {
    event.stopPropagation();
    const card = event.target.closest('.card');
    const name = card.getAttribute('data-name');
    const price = parseFloat(card.getAttribute('data-price'));
    const quantitySpan = card.querySelector('span');
    let quantity = parseInt(quantitySpan.textContent, 10);

    quantity = Math.max(0, quantity + delta);
    quantitySpan.textContent = quantity;

    // Обновление корзины
    if (quantity > 0) {
        cart[name] = { price, quantity };
    } else {
        delete cart[name];
    }

    // Сохраняем обновленную корзину в localStorage
    localStorage.setItem('cart', JSON.stringify(cart));
}

// Переход в корзину
function goToCart() {
    localStorage.setItem('cart', JSON.stringify(cart)); // Сохраняем корзину
    window.location.href = 'cart.php';
}




