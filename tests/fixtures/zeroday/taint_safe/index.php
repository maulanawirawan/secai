<?php
// FP-CONTROL fixture: safe versions; taint_engine must report nothing.
$id = intval($_GET['id']);
$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$_GET['name']]);
system("ping -c 1 " . escapeshellarg($_GET['host']));
echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES);
$n = (int)$_GET['n'];
echo "Count: " . $n;
header("Location: /home");
$prefs = json_decode($_COOKIE['prefs'], true);
