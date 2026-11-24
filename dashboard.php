<?php
require 'includes/session_security.php';
require_login();
$path = auth_dashboard_path($_SESSION['user']['role']);
header('Location: ' . $path);
exit;
