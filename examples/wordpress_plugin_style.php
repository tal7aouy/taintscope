<?php
/**
 * Example: a small WordPress-plugin-style PHP app with several realistic
 * taint vulnerabilities. Point TaintScope at this to see cross-function
 * data-flow detection.
 */

class UserFetcher {
    private $wpdb;

    public function __construct($wpdb) {
        $this->wpdb = $wpdb;
    }

    // SQLi: $_GET['id'] concatenated into a query, no escaping.
    public function getById() {
        $id = $_GET['id'];
        $sql = "SELECT * FROM wp_users WHERE ID = " . $id;
        return $this->wpdb->query($sql);
    }

    // Safe: intval() neutralizes SQLi.
    public function getByIdSafe() {
        $id = intval($_GET['id']);
        $sql = "SELECT * FROM wp_users WHERE ID = " . $id;
        return $this->wpdb->query($sql);
    }
}

// RCE via a helper across functions.
function render_template($name) {
    $path = $_GET['template'];
    load_file($path);
}

function load_file($file) {
    include $file;
}

// XSS via echo, sanitized variant uses htmlspecialchars.
function show_profile() {
    $user = $_GET['user'];
    echo "Welcome, " . $user;
}

function show_profile_safe() {
    $user = htmlspecialchars($_GET['user']);
    echo "Welcome, " . $user;
}
