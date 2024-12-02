<?php
// Подключение к базе данных
require 'includes/db.php';
session_start();

// Обработка формы регистрации
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $confirmPassword = trim($_POST['confirm_password']);

    // Проверка пароля
    if ($password !== $confirmPassword) {
        $error = "Пароли не совпадают.";
    } else {
        // Проверка, существует ли пользователь с таким именем
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $error = "Пользователь с таким логином уже существует.";
        } else {
            // Хэширование пароля
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            // Сохранение нового пользователя
            $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            $stmt->bind_param("ss", $username, $hashedPassword);

            if ($stmt->execute()) {
                $success = "Регистрация успешна! Теперь вы можете <a href='login.php'>войти</a>.";
            } else {
                $error = "Ошибка при создании учетной записи. Попробуйте еще раз.";
            }
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Регистрация</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="login-container">
        <h1>Регистрация</h1>
        <p>Создайте учетную запись для доступа к системе.</p>

        <!-- Сообщение об ошибке или успехе -->
        <?php if (!empty($error)): ?>
            <div class="error-message"><?php echo $error; ?></div>
        <?php endif; ?>
        <?php if (!empty($success)): ?>
            <div class="success-message"><?php echo $success; ?></div>
        <?php endif; ?>

        <form action="register.php" method="POST" class="login-form">
            <div>
                <label for="username">Логин:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div>
                <label for="confirm_password">Подтверждение пароля:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit">Зарегистрироваться</button>
        </form>

        <p>Уже есть аккаунт? <a href="index.php">Вход</a></p>
    </div>
</body>
</html>
