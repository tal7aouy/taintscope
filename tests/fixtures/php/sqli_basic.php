<?php
// Classic SQLi: $_GET flows directly into mysqli_query with no sanitizer.
function get_user($conn) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = " . $id;
    mysqli_query($conn, $sql);
}

// Sanitized variant: should NOT report.
function get_user_safe($conn) {
    $id = $_GET['id'];
    $safe = mysqli_real_escape_string($conn, $id);
    $sql = "SELECT * FROM users WHERE id = '" . $safe . "'";
    mysqli_query($conn, $sql);
}
