<?php

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_PERSISTENT => true,
    PDO::ATTR_STRINGIFY_FETCHES => false,
    PDO::ATTR_EMULATE_PREPARES => false,
];

$dbh = new PDO("mysql:host=db;dbname=zieleniak;charset=utf8", "zieleniak_user", "zieleniak_pass", $options);


