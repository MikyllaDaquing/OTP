<?php
require 'config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $otp = trim($_POST['otp']);

    // Debug: Show what's in database (fixed the reserved keyword issue)
    $check_sql = "SELECT otp_code, otp_expiry, NOW() as current_db_time FROM users WHERE email = ?";
    $check_stmt = $conn->prepare($check_sql);
    
    if (!$check_stmt) {
        die("Prepare failed: " . $conn->error);
    }
    
    $check_stmt->bind_param("s", $email);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        
        // Debug output
        echo "<pre>Database Record:";
        print_r($row);
        echo "Current Time: " . date('Y-m-d H:i:s') . "</pre>";
        
        // Verify OTP and check expiry
        if ($row['otp_code'] == $otp && strtotime($row['otp_expiry']) >= time()) {
            // Mark as verified
            $update_sql = "UPDATE users SET is_verified = 1 WHERE email = ?";
            $update_stmt = $conn->prepare($update_sql);
            
            if (!$update_stmt) {
                die("Prepare failed: " . $conn->error);
            }
            
            $update_stmt->bind_param("s", $email);
            
            if ($update_stmt->execute()) {
                // Redirect to success page
                header("Location: login.php?email=" . urlencode($email));
                exit();
            } else {
                echo "Update failed: " . $update_stmt->error;
            }
        } else {
            if ($row['otp_code'] != $otp) {
                echo "OTP code mismatch. Please try again.";
            } else {
                echo "OTP has expired. Please request a new one.";
            }
        }
    } else {
        echo "No OTP found for this email. Please request a new OTP.";
    }
    
    $check_stmt->close();
}

?>