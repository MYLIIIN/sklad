<?php
$host = 'localhost';
$dbname = 'inventory_system';
$username = 'root';
$password = '';

// Подключение
$conn = new mysqli($host, $username, $password, $dbname);

// Проверка подключения
if ($conn->connect_error) {
    die("Ошибка подключения к базе данных: " . $conn->connect_error);
}
?>
