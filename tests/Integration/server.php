<?php

// Minimal server that echoes a JSON response with the request details.
// Used by integration tests to verify requests actually reach (or don't reach) the server.

header('Content-Type: application/json');
echo json_encode([
    'reached' => true,
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'host' => $_SERVER['HTTP_HOST'] ?? null,
]);
