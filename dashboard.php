<?php
require 'includes/db.php';
session_start();

// Проверка на авторизацию
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

// Получение роли пользователя
$userId = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$stmt->bind_result($role);
$stmt->fetch();
$stmt->close();

// Сохранение роли в сессии
$_SESSION['role'] = $role;

// Если роль недействительна, перенаправляем на страницу входа
if (!in_array($role, ['admin', 'user'])) {
    header("Location: index.php");
    exit;
}

// Обработка добавления товара
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_product'])) {
    if ($_SESSION['role'] !== 'admin') {
        $error = "У вас нет прав для добавления товара.";
    } else {
        $name = trim($_POST['name']);
        $category = trim($_POST['category']);
        $quantity = intval($_POST['quantity']);
        $location = trim($_POST['location']);
        $code = trim($_POST['code']); // Получаем код товара

        if ($name && $category && $quantity >= 0 && $location && $code) {
            $stmt = $conn->prepare("INSERT INTO products (name, category, quantity, location, код) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("ssiss", $name, $category, $quantity, $location, $code); // Добавляем код в запрос
            if ($stmt->execute()) {
                $success = "Товар успешно добавлен!";
            } else {
                $error = "Ошибка при добавлении товара.";
            }
            $stmt->close();
        } else {
            $error = "Все поля должны быть заполнены.";
        }

        // Редирект для предотвращения повторной отправки
        header("Location: dashboard.php");
        exit;
    }
}

// Обработка удаления товара
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_product'])) {
    if ($_SESSION['role'] !== 'admin') {
        $error = "У вас нет прав для удаления товара.";
    } else {
        $delete_code = trim($_POST['delete_id']); // Удаление по коду
        $delete_quantity = intval($_POST['delete_quantity']); // Получаем количество для удаления

        if ($delete_code && $delete_quantity > 0) {
            // Получение текущего количества товара
            $stmt = $conn->prepare("SELECT quantity FROM products WHERE код = ?");
            $stmt->bind_param("s", $delete_code);
            $stmt->execute();
            $stmt->bind_result($current_quantity);
            $stmt->fetch();
            $stmt->close();

            // Проверка на наличие товара и достаточно ли количества
            if ($current_quantity >= $delete_quantity) {
                $new_quantity = $current_quantity - $delete_quantity;

                // Обновление количества товара или удаление, если количество = 0
                if ($new_quantity > 0) {
                    $stmt = $conn->prepare("UPDATE products SET quantity = ? WHERE код = ?");
                    $stmt->bind_param("is", $new_quantity, $delete_code);
                    $stmt->execute();
                    $stmt->close();
                    $success = "Товар с кодом $delete_code успешно обновлён. Осталось $new_quantity единиц.";
                } else {
                    // Удаление товара, если количество 0
                    $stmt = $conn->prepare("DELETE FROM products WHERE код = ?");
                    $stmt->bind_param("s", $delete_code);
                    $stmt->execute();
                    $stmt->close();
                    $success = "Товар с кодом $delete_code был удалён.";
                }
            } else {
                $error = "Недостаточное количество товара для удаления.";
            }
        } else {
            $error = "Введите корректный код товара и количество для удаления.";
        }

        // Редирект для предотвращения повторной отправки
        header("Location: dashboard.php");
        exit;
    }
}

// Обработка поиска товара
$searchQuery = "";
if (isset($_GET['search'])) {
    $searchQuery = trim($_GET['search']);
}

// Получение товаров для отображения в таблице
$sql = "SELECT id, name, category, quantity, location, код FROM products"; // Теперь выбираем также код
if ($searchQuery) {
    $sql .= " WHERE name LIKE ? OR category LIKE ?";
    $stmt = $conn->prepare($sql);
    $likeQuery = "%" . $searchQuery . "%";
    $stmt->bind_param("ss", $likeQuery, $likeQuery);
} else {
    $stmt = $conn->prepare($sql);
}

$stmt->execute();
$result = $stmt->get_result();
$products = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Каталог товаров</title>
    <link rel="stylesheet" href="css/dashboard.css">
</head>
<body>
    <header class="main-header">
        <div class="logo">Мой Склад</div>
        <nav class="navigation">
            <a href="dashboard.php" class="home">Главная</a>
            <a href="logout.php" class="logout">Выход</a>
        </nav>
    </header>

    <div class="dashboard-container">
        <h1>Каталог товаров</h1>

        <!-- Форма добавления товара -->
        <?php if ($_SESSION['role'] === 'admin'): ?>
            <form method="POST" action="dashboard.php" class="form-horizontal">
                <h2>Добавить товар</h2>
                <?php if (!empty($success)): ?>
                    <div class="success-message"><?php echo $success; ?></div>
                <?php endif; ?>
                <?php if (!empty($error)): ?>
                    <div class="error-message"><?php echo $error; ?></div>
                <?php endif; ?>

                <div class="form-row">
                    <input type="text" name="name" placeholder="Название" required>
                    <input type="text" name="category" placeholder="Категория" required>
                    <input type="number" name="quantity" placeholder="Количество" min="0" required>
                    <select name="location" required>
                        <option value="">Выберите место хранения</option>
                        <option value="Комсомольский">Комсомольский</option>
                        <option value="Молодёжная">Молодёжная</option>
                        <option value="Песчаная">Песчаная</option>
                    </select>
                    <input type="text" name="code" placeholder="Код товара" required>
                    <button type="submit" name="add_product">Добавить</button>
                </div>
            </form>
        <?php endif; ?>

        <!-- Таблица каталога -->
        <h2>Каталог</h2>
        <div class="search-bar">
            <form method="GET" action="dashboard.php">
                <input type="text" name="search" placeholder="Введите название или категорию" value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
                <button type="submit">Искать</button>
            </form>
        </div>

        <?php if ($_SESSION['role'] === 'admin'): ?>
            <div class="delete-bar">
                <form method="POST" action="dashboard.php">
                    <div class="form-row">
                        <input type="text" name="delete_id" placeholder="Код товара" required>
                        <input type="number" name="delete_quantity" placeholder="Количество" min="1" required>
                        <button type="submit" name="delete_product">Удалить</button>
                    </div>
                </form>
            </div>
        <?php endif; ?>

        <table class="catalog-table">
            <thead>
                <tr>
                    <th>Код</th>
                    <th>Название</th>
                    <th>Категория</th>
                    <th>Количество</th>
                    <th>Место хранения</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($products)): ?>
                    <tr>
                        <td colspan="5">Товары не найдены.</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($products as $product): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($product['код']); ?></td>
                            <td><?php echo htmlspecialchars($product['name']); ?></td>
                            <td><?php echo htmlspecialchars($product['category']); ?></td>
                            <td><?php echo $product['quantity']; ?></td>
                            <td><?php echo htmlspecialchars($product['location']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
