<?php
session_start();

// Завершение сессии
session_unset();
session_destroy();

// Перенаправление на страницу входа
header("Location: index.php");
exit;
?>
