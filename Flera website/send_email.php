<?php
/**
 * FLERA - Enhanced Security Email Handler
 */

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    // 1. Honeypot Validation (Spam Bot Protection)
    // if the hidden field 'b_address' is filled, it's a bot
    if (!empty($_POST["b_address"])) {
        http_response_code(400);
        exit("Bot detected.");
    }

    // 2. Strict Input Sanitization
    $name       = filter_var(trim($_POST["name"]), FILTER_SANITIZE_SPECIAL_CHARS);
    $phone      = filter_var(trim($_POST["phone"]), FILTER_SANITIZE_NUMBER_INT);
    $email      = filter_var(trim($_POST["email"]), FILTER_SANITIZE_EMAIL);
    $event_type = filter_var($_POST["event_type"], FILTER_SANITIZE_SPECIAL_CHARS);
    $date       = filter_var($_POST["date"], FILTER_SANITIZE_SPECIAL_CHARS);
    $message    = filter_var(trim($_POST["message"]), FILTER_SANITIZE_SPECIAL_CHARS);

    // Validate if the phone is exactly 10 digits long
    if (!preg_match('/^[0-9]{10}$/', $phone)) {
        http_response_code(400);
        echo "Invalid Phone Number. Please enter exactly 10 digits.";
        exit;
    }

    // Validate email format after sanitization
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo "Invalid Email Address";
        exit;
    }

    // 3. Configuration
    $recipient = "hello@flera.in"; 
    $subject   = "New FLERA Inquiry: $event_type from $name";

    // 4. Email Content Construction
    $email_content  = "You have a new inquiry from the FLERA website:\n\n";
    $email_content .= "Name: $name\n";
    $email_content .= "Phone: $phone\n";
    $email_content .= "Email: $email\n";
    $email_content .= "Event: $event_type\n";
    $email_content .= "Date: $date\n\n";
    $email_content .= "Message:\n$message\n";

    // 5. Enhanced Security Headers
    // Using hello@flera.in as 'From' to ensure server deliverability
    // Setting 'Reply-To' as the customer's email for easy communication
    $headers = [
        "From"         => "FLERA Web <hello@flera.in>",
        "Reply-To"     => "$name <$email>",
        "X-Mailer"     => "PHP/" . phpversion(),
        "Content-Type" => "text/plain; charset=UTF-8"
    ];

    // 6. Execution
    if (mail($recipient, $subject, $email_content, $headers)) {
        http_response_code(200);
        echo "Success";
    } else {
        http_response_code(500);
        echo "Error: The server was unable to send the email.";
    }
} else {
    http_response_code(403);
    echo "Access Denied";
}
?>