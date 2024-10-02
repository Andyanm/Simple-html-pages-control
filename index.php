<?php
session_start();

// Configuration
define('DB_FILE', __DIR__ . '/pages.db');
define('ADMIN_USERNAME', 'admin');
define('DEFAULT_ADMIN_PASSWORD', '123456'); // Initial password

// Initialize Database
function init_db()
{
    if (!file_exists(DB_FILE)) {
        try {
            $db = new PDO('sqlite:' . DB_FILE);
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Create pages table
            $db->exec("
                CREATE TABLE IF NOT EXISTS pages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    slug TEXT NOT NULL UNIQUE,
                    html_content TEXT NOT NULL,
                    css_content TEXT,
                    js_content TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ");

            // Create admin table
            $db->exec("
                CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
            ");

            // Insert default admin
            $stmt = $db->prepare("INSERT INTO admin (username, password_hash) VALUES (:username, :password_hash)");
            $stmt->execute([
                ':username' => ADMIN_USERNAME,
                ':password_hash' => password_hash(DEFAULT_ADMIN_PASSWORD, PASSWORD_DEFAULT)
            ]);
        } catch (PDOException $e) {
            die("Database initialization failed: " . htmlspecialchars($e->getMessage()));
        }
    }
}

// Get Database Connection
function get_db_connection()
{
    try {
        $db = new PDO('sqlite:' . DB_FILE);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $db;
    } catch (PDOException $e) {
        die("Database connection failed: " . htmlspecialchars($e->getMessage()));
    }
}

// Sanitize Input
function sanitize_input($data)
{
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// Generate CSRF Token
function generate_csrf_token()
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Verify CSRF Token
function verify_csrf_token($token)
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Check if Admin is Logged In
function is_admin_logged_in()
{
    return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

// Redirect Function
function redirect($url)
{
    header("Location: $url");
    exit;
}

// Handle Login
function handle_login($db)
{
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        if (!verify_csrf_token($_POST['csrf_token'])) {
            $error = "Invalid CSRF token.";
        } else {
            $username = sanitize_input($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            $stmt = $db->prepare("SELECT * FROM admin WHERE username = :username");
            $stmt->execute([':username' => $username]);
            $admin = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($admin && password_verify($password, $admin['password_hash'])) {
                // Successful login
                session_regenerate_id(true);
                $_SESSION['admin_logged_in'] = true;
                redirect('index.php?admin=dashboard');
            } else {
                $error = "Invalid username or password.";
            }
        }
    }

    // Display Login Form
    $csrf_token = generate_csrf_token();
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .login-container { width: 350px; margin: 100px auto; padding: 30px; background-color: #fff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        h2 { text-align: center; margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 10px; background-color: #4CAF50; border: none; border-radius: 4px; color: white; font-size: 16px; cursor: pointer; }
        button:hover { background-color: #45a049; }
        .error { color: red; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Admin Login</h2>
        <form method="POST" action="index.php?admin=login">
            <input type="hidden" name="csrf_token" value="{$csrf_token}">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required autofocus>
            
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            
            <button type="submit" name="login">Login</button>
        </form>
HTML;
    if (!empty($error)) {
        echo "<div class='error'>" . htmlspecialchars($error) . "</div>";
    }
    echo <<<HTML
    </div>
</body>
</html>
HTML;
    exit;
}

// Handle Logout
function handle_logout()
{
    session_unset();
    session_destroy();
    redirect('index.php?admin=login');
}

// Show Admin Dashboard
function show_dashboard($db)
{
    // Handle success messages
    $message = '';
    if (isset($_GET['message'])) {
        $msg = sanitize_input($_GET['message']);
        switch ($msg) {
            case 'added':
                $message = "Page added successfully.";
                break;
            case 'updated':
                $message = "Page updated successfully.";
                break;
            case 'deleted':
                $message = "Page deleted successfully.";
                break;
            case 'password_changed':
                $message = "Password changed successfully.";
                break;
            case 'error':
                $message = "Operation failed. Please try again.";
                break;
            default:
                $message = "";
        }
    }

    // Fetch all pages
    $stmt = $db->query("SELECT * FROM pages ORDER BY created_at DESC");
    $pages = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Display Dashboard
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; }
        .logout { text-decoration: none; color: #f44336; }
        .logout:hover { text-decoration: underline; }
        .message { padding: 10px; margin: 20px 0; border-radius: 4px; background-color: #dff0d8; color: #3c763d; }
        .error { padding: 10px; margin: 20px 0; border-radius: 4px; background-color: #f2dede; color: #a94442; }
        table { width: 100%; border-collapse: collapse; background-color: #fff; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        a { color: #4CAF50; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .add-button, .change-password-button { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; border-radius: 4px; text-decoration: none; margin-bottom: 20px; margin-right: 10px; }
        .add-button:hover, .change-password-button:hover { background-color: #45a049; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Admin Dashboard</h1>
        <a href="index.php?action=logout" class="logout">Logout</a>
    </div>
HTML;
    if (!empty($message)) {
        echo "<div class='message'>" . htmlspecialchars($message) . "</div>";
    }

    echo <<<HTML
    <a href="index.php?admin=add" class="add-button">Add New Page</a>
    <a href="index.php?admin=change_password" class="change-password-button">Change Password</a>
    <table>
        <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Slug</th>
            <th>Created At</th>
            <th>Actions</th>
        </tr>
HTML;

    if ($pages) {
        foreach ($pages as $page) {
            $id = htmlspecialchars($page['id']);
            $title = htmlspecialchars($page['title']);
            $slug = htmlspecialchars($page['slug']);
            $created_at = htmlspecialchars($page['created_at']);
            echo <<<HTML
        <tr>
            <td>{$id}</td>
            <td>{$title}</td>
            <td><a href="index.php?slug={$slug}" target="_blank">{$slug}</a></td>
            <td>{$created_at}</td>
            <td>
                <a href="index.php?admin=edit&id={$id}">Edit</a> | 
                <a href="index.php?admin=delete&id={$id}" onclick="return confirm('Are you sure you want to delete this page?');">Delete</a>
            </td>
        </tr>
HTML;
        }
    } else {
        echo <<<HTML
        <tr>
            <td colspan="5" style="text-align:center;">No pages found.</td>
        </tr>
HTML;
    }

    echo <<<HTML
    </table>
</body>
</html>
HTML;
    exit;
}

// Show Add Page Form
function show_add_page($db)
{
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_page'])) {
        if (!verify_csrf_token($_POST['csrf_token'])) {
            $error = "Invalid CSRF token.";
        } else {
            $title = sanitize_input($_POST['title'] ?? '');
            $slug = sanitize_input($_POST['slug'] ?? '');
            $html_content = trim($_POST['html_content'] ?? '');
            $css_content = trim($_POST['css_content'] ?? '');
            $js_content = trim($_POST['js_content'] ?? '');

            // Validate inputs
            if (empty($title) || empty($slug) || empty($html_content)) {
                $error = "Title, Slug, and HTML Content are required.";
            } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
                $error = "Slug can only contain letters, numbers, underscores, and hyphens.";
            } else {
                // Check if slug is unique
                $stmt = $db->prepare("SELECT COUNT(*) FROM pages WHERE slug = :slug");
                $stmt->execute([':slug' => $slug]);
                if ($stmt->fetchColumn() > 0) {
                    $error = "The slug already exists. Please choose a different slug.";
                } else {
                    // Insert new page
                    $stmt = $db->prepare("INSERT INTO pages (title, slug, html_content, css_content, js_content) VALUES (:title, :slug, :html_content, :css_content, :js_content)");
                    $result = $stmt->execute([
                        ':title' => $title,
                        ':slug' => $slug,
                        ':html_content' => $html_content,
                        ':css_content' => $css_content,
                        ':js_content' => $js_content
                    ]);

                    if ($result) {
                        redirect('index.php?admin=dashboard&message=added');
                    } else {
                        $error = "Failed to add the page. Please try again.";
                    }
                }
            }
        }
    }

    // Display Add Page Form
    $csrf_token = generate_csrf_token();
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Add New Page</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; }
        .logout { text-decoration: none; color: #f44336; }
        .logout:hover { text-decoration: underline; }
        .back-link { margin: 20px 0; }
        .back-link a { text-decoration: none; color: #4CAF50; }
        .back-link a:hover { text-decoration: underline; }
        form { max-width: 800px; margin: 0 auto; }
        label { display: block; margin-top: 15px; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], textarea { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        textarea { resize: vertical; height: 200px; }
        .submit-button { margin-top: 20px; text-align: center; }
        .submit-button button { padding: 10px 20px; background-color: #4CAF50; border: none; border-radius: 4px; color: white; font-size: 16px; cursor: pointer; }
        .submit-button button:hover { background-color: #45a049; }
        .error { color: red; text-align: center; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Add New Page</h1>
        <a href="index.php?action=logout" class="logout">Logout</a>
    </div>
    <div class="back-link">
        <a href="index.php?admin=dashboard">&larr; Back to Dashboard</a>
    </div>
HTML;
    if (!empty($error)) {
        echo "<div class='error'>" . htmlspecialchars($error) . "</div>";
    }

    echo <<<HTML
    <form method="POST" action="index.php?admin=add">
        <input type="hidden" name="csrf_token" value="{$csrf_token}">
        
        <label for="title">Title *</label>
        <input type="text" id="title" name="title" required>
        
        <label for="slug">Slug (URL) *</label>
        <input type="text" id="slug" name="slug" required pattern="[a-zA-Z0-9_-]+" title="Only letters, numbers, underscores, and hyphens are allowed.">
        
        <label for="html_content">HTML Content *</label>
        <textarea id="html_content" name="html_content" required></textarea>
        
        <label for="css_content">CSS Content (Optional)</label>
        <textarea id="css_content" name="css_content"></textarea>
        
        <label for="js_content">JavaScript Content (Optional)</label>
        <textarea id="js_content" name="js_content"></textarea>
        
        <div class="submit-button">
            <button type="submit" name="add_page">Add Page</button>
        </div>
    </form>
</body>
</html>
HTML;
    exit;
}

// Show Edit Page Form
function show_edit_page($db, $page_id)
{
    $error = '';
    // Fetch page data
    $stmt = $db->prepare("SELECT * FROM pages WHERE id = :id");
    $stmt->execute([':id' => $page_id]);
    $page = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$page) {
        redirect('index.php?admin=dashboard&message=error');
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_page'])) {
        if (!verify_csrf_token($_POST['csrf_token'])) {
            $error = "Invalid CSRF token.";
        } else {
            $title = sanitize_input($_POST['title'] ?? '');
            $slug = sanitize_input($_POST['slug'] ?? '');
            $html_content = trim($_POST['html_content'] ?? '');
            $css_content = trim($_POST['css_content'] ?? '');
            $js_content = trim($_POST['js_content'] ?? '');

            // Validate inputs
            if (empty($title) || empty($slug) || empty($html_content)) {
                $error = "Title, Slug, and HTML Content are required.";
            } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
                $error = "Slug can only contain letters, numbers, underscores, and hyphens.";
            } else {
                // Check if slug is unique for other pages
                $stmt = $db->prepare("SELECT COUNT(*) FROM pages WHERE slug = :slug AND id != :id");
                $stmt->execute([':slug' => $slug, ':id' => $page_id]);
                if ($stmt->fetchColumn() > 0) {
                    $error = "The slug already exists for another page. Please choose a different slug.";
                } else {
                    // Update the page
                    $stmt = $db->prepare("UPDATE pages SET title = :title, slug = :slug, html_content = :html_content, css_content = :css_content, js_content = :js_content, updated_at = CURRENT_TIMESTAMP WHERE id = :id");
                    $result = $stmt->execute([
                        ':title' => $title,
                        ':slug' => $slug,
                        ':html_content' => $html_content,
                        ':css_content' => $css_content,
                        ':js_content' => $js_content,
                        ':id' => $page_id
                    ]);

                    if ($result) {
                        redirect('index.php?admin=dashboard&message=updated');
                    } else {
                        $error = "Failed to update the page. Please try again.";
                    }
                }
            }
        }
    }

    // Display Edit Page Form
    $csrf_token = generate_csrf_token();
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edit Page</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; }
        .logout { text-decoration: none; color: #f44336; }
        .logout:hover { text-decoration: underline; }
        .back-link { margin: 20px 0; }
        .back-link a { text-decoration: none; color: #4CAF50; }
        .back-link a:hover { text-decoration: underline; }
        form { max-width: 800px; margin: 0 auto; }
        label { display: block; margin-top: 15px; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], textarea { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        textarea { resize: vertical; height: 200px; }
        .submit-button { margin-top: 20px; text-align: center; }
        .submit-button button { padding: 10px 20px; background-color: #4CAF50; border: none; border-radius: 4px; color: white; font-size: 16px; cursor: pointer; }
        .submit-button button:hover { background-color: #45a049; }
        .error { color: red; text-align: center; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Edit Page</h1>
        <a href="index.php?action=logout" class="logout">Logout</a>
    </div>
    <div class="back-link">
        <a href="index.php?admin=dashboard">&larr; Back to Dashboard</a>
    </div>
HTML;
    if (!empty($error)) {
        echo "<div class='error'>" . htmlspecialchars($error) . "</div>";
    }

    // Populate form with existing data
    $title = htmlspecialchars($page['title']);
    $slug = htmlspecialchars($page['slug']);
    $html_content = htmlspecialchars($page['html_content']);
    $css_content = htmlspecialchars($page['css_content']);
    $js_content = htmlspecialchars($page['js_content']);

    echo <<<HTML
    <form method="POST" action="index.php?admin=edit&id={$page_id}">
        <input type="hidden" name="csrf_token" value="{$csrf_token}">
        
        <label for="title">Title *</label>
        <input type="text" id="title" name="title" required value="{$title}">
        
        <label for="slug">Slug (URL) *</label>
        <input type="text" id="slug" name="slug" required pattern="[a-zA-Z0-9_-]+" title="Only letters, numbers, underscores, and hyphens are allowed." value="{$slug}">
        
        <label for="html_content">HTML Content *</label>
        <textarea id="html_content" name="html_content" required>{$html_content}</textarea>
        
        <label for="css_content">CSS Content (Optional)</label>
        <textarea id="css_content" name="css_content">{$css_content}</textarea>
        
        <label for="js_content">JavaScript Content (Optional)</label>
        <textarea id="js_content" name="js_content">{$js_content}</textarea>
        
        <div class="submit-button">
            <button type="submit" name="edit_page">Update Page</button>
        </div>
    </form>
</body>
</html>
HTML;
    exit;
}

// Handle Delete Page
function handle_delete_page($db, $page_id)
{
    // Delete the page
    $stmt = $db->prepare("DELETE FROM pages WHERE id = :id");
    $result = $stmt->execute([':id' => $page_id]);

    if ($result) {
        redirect('index.php?admin=dashboard&message=deleted');
    } else {
        redirect('index.php?admin=dashboard&message=error');
    }
}

// Show Change Password Form
function show_change_password($db)
{
    $error = '';
    $success = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
        if (!verify_csrf_token($_POST['csrf_token'])) {
            $error = "Invalid CSRF token.";
        } else {
            $current_password = $_POST['current_password'] ?? '';
            $new_password = $_POST['new_password'] ?? '';
            $confirm_password = $_POST['confirm_password'] ?? '';

            // Validate inputs
            if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
                $error = "All fields are required.";
            } elseif ($new_password !== $confirm_password) {
                $error = "New password and confirmation do not match.";
            } elseif (strlen($new_password) < 8) { // Adjust password strength as needed
                $error = "New password must be at least 8 characters long.";
            } else {
                // Fetch current admin password hash
                $stmt = $db->prepare("SELECT * FROM admin WHERE username = :username");
                $stmt->execute([':username' => ADMIN_USERNAME]);
                $admin = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($admin && password_verify($current_password, $admin['password_hash'])) {
                    // Update password
                    $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);
                    $update_stmt = $db->prepare("UPDATE admin SET password_hash = :password_hash WHERE id = :id");
                    $update_result = $update_stmt->execute([
                        ':password_hash' => $new_password_hash,
                        ':id' => $admin['id']
                    ]);

                    if ($update_result) {
                        $success = "Password changed successfully.";
                        // Regenerate CSRF token
                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    } else {
                        $error = "Failed to change password. Please try again.";
                    }
                } else {
                    $error = "Current password is incorrect.";
                }
            }
        }
    }

    // Display Change Password Form
    $csrf_token = generate_csrf_token();
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Change Password</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; }
        .logout { text-decoration: none; color: #f44336; }
        .logout:hover { text-decoration: underline; }
        .back-link { margin: 20px 0; }
        .back-link a { text-decoration: none; color: #4CAF50; }
        .back-link a:hover { text-decoration: underline; }
        form { max-width: 500px; margin: 0 auto; }
        label { display: block; margin-top: 15px; margin-bottom: 5px; font-weight: bold; }
        input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        .submit-button { margin-top: 20px; text-align: center; }
        .submit-button button { padding: 10px 20px; background-color: #4CAF50; border: none; border-radius: 4px; color: white; font-size: 16px; cursor: pointer; }
        .submit-button button:hover { background-color: #45a049; }
        .error { color: red; text-align: center; margin-bottom: 15px; }
        .success { color: green; text-align: center; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Change Password</h1>
        <a href="index.php?action=logout" class="logout">Logout</a>
    </div>
    <div class="back-link">
        <a href="index.php?admin=dashboard">&larr; Back to Dashboard</a>
    </div>
HTML;
    if (!empty($error)) {
        echo "<div class='error'>" . htmlspecialchars($error) . "</div>";
    }
    if (!empty($success)) {
        echo "<div class='success'>" . htmlspecialchars($success) . "</div>";
    }

    echo <<<HTML
    <form method="POST" action="index.php?admin=change_password">
        <input type="hidden" name="csrf_token" value="{$csrf_token}">
        
        <label for="current_password">Current Password *</label>
        <input type="password" id="current_password" name="current_password" required>
        
        <label for="new_password">New Password *</label>
        <input type="password" id="new_password" name="new_password" required>
        
        <label for="confirm_password">Confirm New Password *</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
        
        <div class="submit-button">
            <button type="submit" name="change_password">Change Password</button>
        </div>
    </form>
</body>
</html>
HTML;
    exit;
}

// Serve CSS or JS Resource
function serve_resource($db, $slug, $resource)
{
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
        http_response_code(400);
        echo "Invalid slug.";
        exit;
    }

    $stmt = $db->prepare("SELECT * FROM pages WHERE slug = :slug");
    $stmt->execute([':slug' => $slug]);
    $page = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$page) {
        http_response_code(404);
        echo "Page not found.";
        exit;
    }

    if ($resource === 'css' && !empty($page['css_content'])) {
        header("Content-Type: text/css; charset=UTF-8");
        echo $page['css_content'];
        exit;
    } elseif ($resource === 'js' && !empty($page['js_content'])) {
        header("Content-Type: application/javascript; charset=UTF-8");
        echo $page['js_content'];
        exit;
    } else {
        http_response_code(404);
        echo "Resource not found.";
        exit;
    }
}

// Serve Standalone Page
function serve_page($db, $slug)
{
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
        http_response_code(400);
        echo "Invalid slug.";
        exit;
    }

    $stmt = $db->prepare("SELECT * FROM pages WHERE slug = :slug");
    $stmt->execute([':slug' => $slug]);
    $page = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($page) {
        // Serve the standalone HTML page
        echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{$page['title']}</title>
HTML;
        // Include CSS if available
        if (!empty($page['css_content'])) {
            echo '<style>' . $page['css_content'] . '</style>';
        }

        echo <<<HTML
</head>
<body>
    {$page['html_content']}
HTML;
        // Include JS if available
        if (!empty($page['js_content'])) {
            echo '<script>' . $page['js_content'] . '</script>';
        }

        echo <<<HTML
</body>
</html>
HTML;
        exit;
    } else {
        http_response_code(404);
        echo "Page not found.";
        exit;
    }
}

// Handle Request and Route
function route_request()
{
    init_db();
    $db = get_db_connection();

    // Handle Logout
    if (isset($_GET['action']) && $_GET['action'] === 'logout') {
        handle_logout();
    }

    // Handle Admin Actions
    if (isset($_GET['admin'])) {
        $admin_action = $_GET['admin'];

        if ($admin_action === 'login') {
            if (is_admin_logged_in()) {
                redirect('index.php?admin=dashboard');
            }
            handle_login($db);
        } elseif ($admin_action === 'dashboard') {
            if (!is_admin_logged_in()) {
                redirect('index.php?admin=login');
            }
            show_dashboard($db);
        } elseif ($admin_action === 'add') {
            if (!is_admin_logged_in()) {
                redirect('index.php?admin=login');
            }
            show_add_page($db);
        } elseif ($admin_action === 'edit' && isset($_GET['id'])) {
            if (!is_admin_logged_in()) {
                redirect('index.php?admin=login');
            }
            $page_id = intval($_GET['id']);
            show_edit_page($db, $page_id);
        } elseif ($admin_action === 'delete' && isset($_GET['id'])) {
            if (!is_admin_logged_in()) {
                redirect('index.php?admin=login');
            }
            $page_id = intval($_GET['id']);
            handle_delete_page($db, $page_id);
        } elseif ($admin_action === 'change_password') {
            if (!is_admin_logged_in()) {
                redirect('index.php?admin=login');
            }
            show_change_password($db);
        } else {
            // Invalid admin action
            redirect('index.php?admin=login');
        }
    }

    // Handle CSS or JS Resource Requests
    if (isset($_GET['slug']) && isset($_GET['resource'])) {
        $slug = sanitize_input($_GET['slug']);
        $resource = sanitize_input($_GET['resource']);

        serve_resource($db, $slug, $resource);
    }

    // Handle Frontend Page Display
    if (isset($_GET['slug'])) {
        $slug = sanitize_input($_GET['slug']);
        serve_page($db, $slug);
    }

    // Default: Redirect to Login Page
    redirect('index.php?admin=login');
}

// Start Routing
route_request();
?>
