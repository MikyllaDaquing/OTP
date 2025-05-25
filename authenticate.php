<?php
session_start();
require 'config.php'; // Your database connection file

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username_email = trim($_POST['username']); // Or $_POST['email'] depending on your form
    $password = $_POST['password'];

    // Database query to find the user
    $sql = "SELECT user_id, email, password, is_verified FROM users WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username_email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();
        $user_id = $row['user_id'];
        $email = $row['email'];
        $hashed_password = $row['password'];
        $is_verified = $row['is_verified'];

        // Verify password
        if (password_verify($password, $hashed_password)) {
            // Check if the user is verified (optional, but good practice)
            if ($is_verified == 1) {
                // Successful login
                $_SESSION['user_id'] = $user_id;
                $_SESSION['email'] = $email;
                header("Location: daquing.html");
                exit();
            } else {
                // Account not verified (shouldn't happen if they reached login.php)
                $login_error = "Your account has not been verified. Please check your email.";
                header("Location: login.php?error=" . urlencode($login_error) . "&email=" . urlencode($email));
                exit();
            }
        } else {
            // Incorrect password
            $login_error = "Incorrect password.";
            header("Location: login.php?error=" . urlencode($login_error) . "&email=" . urlencode($username_email));
            exit();
        }
    } else {
        // User not found
        $login_error = "Invalid username or email.";
        header("Location: login.php?error=" . urlencode($login_error));
        exit();
    }

    $stmt->close();
    $conn->close();
} else {
    // If someone tries to access authenticate.php directly without POST
    header("Location: login.php");
    exit();
}
?>