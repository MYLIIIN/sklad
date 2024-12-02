<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Подключение к базе данных
require 'includes/db.php';
session_start();

// Обработка формы входа
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Проверяем пользователя в базе данных
    $stmt = $conn->prepare("SELECT id, password, role FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($userId, $hashedPassword, $role);
        $stmt->fetch();

        // Проверка пароля
        if (password_verify($password, $hashedPassword)) {
            $_SESSION['user_id'] = $userId;
            $_SESSION['role'] = $role;

            // Перенаправление на панель управления
            header("Location: dashboard.php");
            exit;
        } else {
            $error = "Неправильный пароль.";
        }
    } else {
        $error = "Пользователь не найден.";
    }
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в систему</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="login-container">
        <h1>Добро пожаловать!</h1>
        <p>Система управления запасами на складе.</p>

        <!-- Сообщение об ошибке -->
        <?php if (!empty($error)): ?>
            <div class="error-message"><?php echo $error; ?></div>
        <?php endif; ?>

        <form action="index.php" method="POST" class="login-form">
            <div>
                <label for="username">Логин:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Войти</button>
        </form>

        <p>Нет аккаунта? <a href="register.php">Регистрация</a></p>
    </div>
</body>
</html>
