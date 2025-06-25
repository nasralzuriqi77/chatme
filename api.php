<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

require_once 'db.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

$action = $_GET['action'] ?? '';

$db = new Database();
$conn = $db->getConnection();

switch ($action) {
    case 'register':
        registerUser($conn);
        break;
    case 'login':
        loginUser($conn);
        break;
    case 'getUsers':
        getUsers($conn);
        break;
    case 'sendMessage':
        sendMessage($conn);
        break;
    case 'getMessages':
        getMessages($conn);
        break;
    case 'getUnreadMessages':
        getUnreadMessages($conn);
        break;
    case 'editMessage':
        editMessage($conn);
        break;
    case 'deleteMessage':
        deleteMessage($conn);
        break;
    default:
        echo json_encode(['error' => 'Invalid action']);
        break;
}

function registerUser($conn) {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    if (empty($username) || empty($password)) {
        echo json_encode(['error' => 'Username and password are required']);
        return;
    }

    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    try {
        $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->execute([$username, $hashedPassword]);
        echo json_encode(['success' => true, 'message' => 'User registered successfully']);
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) {
            echo json_encode(['error' => 'Username already exists']);
        } else {
            echo json_encode(['error' => 'Registration failed: ' . $e->getMessage()]);
        }
    }
}

function loginUser($conn) {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    if (empty($username) || empty($password)) {
        echo json_encode(['error' => 'Username and password are required']);
        return;
    }

    $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        session_start();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        echo json_encode([
            'success' => true, 
            'user' => [
                'id' => $user['id'],
                'username' => $user['username']
            ]
        ]);
    } else {
        echo json_encode(['error' => 'Invalid username or password']);
    }
}

function getUsers($conn) {
    session_start();
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not authenticated']);
        return;
    }

    $currentUserId = $_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT id, username FROM users WHERE id != ?");
    $stmt->execute([$currentUserId]);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['success' => true, 'users' => $users]);
}

function sendMessage($conn) {
    session_start();
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not authenticated']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true);
    $receiverId = $data['receiver_id'] ?? 0;
    $message = $data['message'] ?? '';

    if (empty($receiverId) || empty($message)) {
        echo json_encode(['error' => 'Receiver ID and message are required']);
        return;
    }

    $senderId = $_SESSION['user_id'];

    try {
        $stmt = $conn->prepare("INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)");
        $stmt->execute([$senderId, $receiverId, $message]);
        echo json_encode(['success' => true, 'message' => 'Message sent successfully']);
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Failed to send message: ' . $e->getMessage()]);
    }
}

function getMessages($conn) {
    session_start();
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not authenticated']);
        return;
    }

    $currentUserId = $_SESSION['user_id'];
    $otherUserId = $_GET['user_id'] ?? 0;

    if (empty($otherUserId)) {
        echo json_encode(['error' => 'User ID is required']);
        return;
    }

    // Mark messages as read
    $conn->prepare("UPDATE messages SET is_read = TRUE WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE")
         ->execute([$otherUserId, $currentUserId]);

    $stmt = $conn->prepare("
        SELECT m.id, m.sender_id, m.receiver_id, m.message, m.sent_at, m.is_deleted, u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.sent_at ASC
    ");
    $stmt->execute([$currentUserId, $otherUserId, $otherUserId, $currentUserId]);
    $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['success' => true, 'messages' => $messages]);
}

function getUnreadMessages($conn) {
    session_start();
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not authenticated']);
        return;
    }

    $currentUserId = $_SESSION['user_id'];

    $stmt = $conn->prepare("
        SELECT COUNT(*) as unread_count
        FROM messages
        WHERE receiver_id = ? AND is_read = FALSE
    ");
    $stmt->execute([$currentUserId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    echo json_encode(['success' => true, 'unread_count' => $result['unread_count']]);
}

function editMessage($conn) {
    session_start();
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not authenticated']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true);
    $messageId = $data['message_id'] ?? 0;
    $newMessage = $data['new_message'] ?? '';

    if (empty($messageId) || empty($newMessage)) {
        echo json_encode(['error' => 'Message ID and new message are required']);
        return;
    }

    // Verify the message belongs to the current user
    $stmt = $conn->prepare("SELECT sender_id FROM messages WHERE id = ? AND is_deleted = FALSE");
    $stmt->execute([$messageId]);
    $message = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$message || $message['sender_id'] != $_SESSION['user_id']) {
        echo json_encode(['error' => 'You can only edit your own messages']);
        return;
    }

    try {
        $stmt = $conn->prepare("UPDATE messages SET message = ? WHERE id = ?");
        $stmt->execute([$newMessage, $messageId]);
        echo json_encode(['success' => true, 'message' => 'Message updated successfully']);
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Failed to update message: ' . $e->getMessage()]);
    }
}

function deleteMessage($conn) {
    session_start();
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not authenticated']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true);
    $messageId = $data['message_id'] ?? 0;

    if (empty($messageId)) {
        echo json_encode(['error' => 'Message ID is required']);
        return;
    }

    // Verify the message belongs to the current user
    $stmt = $conn->prepare("SELECT sender_id FROM messages WHERE id = ? AND is_deleted = FALSE");
    $stmt->execute([$messageId]);
    $message = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$message || $message['sender_id'] != $_SESSION['user_id']) {
        echo json_encode(['error' => 'You can only delete your own messages']);
        return;
    }

    try {
        // Soft delete the message
        $stmt = $conn->prepare("UPDATE messages SET is_deleted = TRUE WHERE id = ?");
        $stmt->execute([$messageId]);
        echo json_encode(['success' => true, 'message' => 'Message deleted successfully']);
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Failed to delete message: ' . $e->getMessage()]);
    }
}
?>