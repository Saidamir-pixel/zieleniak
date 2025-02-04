<?php
include "db.php";
include "user.php";


function reg(){
    $auth = user_reg();
    return $auth;
}

function login() {
    $login = user_login();
    return $login;
}

function token() {
    $token = user_token();
    return $token;
}

function order() {
    $order = user_order();
    return $order;
}

function greenPoints() {
    $greenPoints = user_greenPoints();
    return $greenPoints;
}

function update() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        update_user();
    }
}


