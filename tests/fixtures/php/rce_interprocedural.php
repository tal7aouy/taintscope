<?php
// RCE via exec, with interprocedural taint through a helper.
function run_cmd($cmd) {
    exec($cmd);
}

function handle_request() {
    $user_input = $_POST['cmd'];
    run_cmd($user_input);
}

// Path traversal via include.
function load_template() {
    $page = $_GET['page'];
    include $page;
}

// XSS via echo.
function greet() {
    $name = $_GET['name'];
    echo $name;
}

// Safe XSS: htmlspecialchars neutralizes it.
function greet_safe() {
    $name = $_GET['name'];
    echo htmlspecialchars($name);
}
