<?php
// DELIBERATELY VULNERABLE fixture for tools/taint_engine.py — never run.
$id = $_GET['id'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
system("ping -c 1 " . $_GET['host']);
include($_GET['page'] . ".php");
$prefs = unserialize($_COOKIE['prefs']);
echo "Hello " . $_GET['name'];
header("Location: " . $_GET['next']);
