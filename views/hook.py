from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes
)

TOKEN = "7845380928:AAHcaQkn71lxNNdj1JRpnaqquzGdcYr3PNI"

# Команда /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Добро пожаловать! Используйте команды /enable и /disable.")

# Команда /enable
async def enable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    with open('settings.json', 'w') as file:
        file.write('{"orders_enabled": true}')
    await update.message.reply_text("Заказы включены!")

# Команда /disable
async def disable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    with open('settings.json', 'w') as file:
        file.write('{"orders_enabled": false}')
    await update.message.reply_text("Заказы отключены!")

# Обработка inline-кнопок
async def handle_button_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data
    if data.startswith("missing_products_"):
        order_id = data.split("_")[-1]
        await query.edit_message_text(f"Укажите недостающие продукты для заказа {order_id}:")
    elif data.startswith("order_ready_"):
        order_id = data.split("_")[-1]
        await query.edit_message_text(f"Заказ {order_id} готов!")
    elif data.startswith("order_paid_"):
        order_id = data.split("_")[-1]
        await query.edit_message_text(f"Заказ {order_id} оплачен!")

def main():
    print("Bot started", flush=True)


    application = Application.builder().token(TOKEN).build()

    # Регистрируем хендлеры команд
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("enable", enable))
    application.add_handler(CommandHandler("disable", disable))

    # Регистрируем хендлер inline-кнопок
    application.add_handler(CallbackQueryHandler(handle_button_click))

    # Запуск бота (блокирующая операция)
    application.run_polling()

if __name__ == "__main__":
    main()
