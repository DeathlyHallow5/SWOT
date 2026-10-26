<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Web Osint Tool</title>
    <style>
body {
    font-family: Arial, sans-serif;
    margin: 20px;
    background-color: black;
    display: flex;
    flex-wrap: wrap; 
    justify-content: center;
    align-items: flex-start;
}

.container {
    display: flex;
    flex-wrap: wrap; 
    max-width: 1200px; 
    margin: 40px;
    margin-top:60px;
    background-color:gray;
            border: 20px solid grey;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
    justify-content: center;
}
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: white;
            text-align: center;
        }
        input[type="text"] {
            width: calc(100% - 20px); 
            padding: 8px;
            box-sizing: border-box;
            margin-left: 10px;
            font-size: 15px;
            text-align: center;
        }
        button {
            padding: 10px 15px;
            background-color: #902537;
            color: white;
            border: none;
            cursor: pointer;
            border-radius: 5px;
        }
        button:hover {
            background-color: #960018;
            border-radius: 10px;
        }
        .results {
            margin-top: 20px;
            padding: 10px;
            border: 1px solid #ccc;
            background-color: #f9f9f9;
            position: relative;
            overflow-wrap: break-word;
            word-wrap: break-word;
            word-break: break-all;
            hyphens: auto;
        }
        .copy-button {
            position: absolute;
            top: 10px;
            right: 10px;
            padding: 5px 10px;
            background-color: #902537;
            color: white;
            border: none;
            cursor: pointer;
            border-radius: 5px;
        }
        .copy-button:hover {
            background-color: #902537;
            border-radius: 10px;
        }
.card {
    background-color: #f4f4f4;
    padding: 20px;
    width: 350px; 
    box-sizing: border-box;
    position: relative;
}
        .card h2 {
            margin-bottom: 15px;
            color: white;
            text-align: center;
        }
        .buttons-container {
            display: flex;
            justify-content: center;
            margin-top: 10px;
        }
        .what-button {
            background-color: #902537;
        }
        .what-button:hover {
            background-color: #902537;
        }
        .nslookup-button {
            background-color: #902537;
        }
        .nslookup-button:hover {
            background-color: #902537;
        }
        .wayback-button {
            background-color: #902537;
        }
        .wayback-button:hover {
            background-color: #902537;
        }

    </style>
</head>
<body>

    <div class="container">
        <div class="card">
            <h2 style="color:black;" >IP LookUP and subdomain Scan</h2>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label style="color:black;" for="nslookup_domain">Enter Domain:</label>
                    <input type="text" id="nslookup_domain" name="nslookup_domain" placeholder="example.com" required>
                </div>
                <div class="buttons-container">
                    <button type="submit" name="nslookup_scan" class="nslookup-button">Start Scan</button>
                </div>
            </form>

           
            <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['nslookup_scan'])): ?>
                <div class="results" id="results">
                    <button class="copy-button" onclick="copyToClipboard()">Copy to Clipboard</button>
                    <h2 style="color:black;" >IP LookUP and subdomains Results:</h2>
                    <?php
                    
$subdomains = [
    "ftp", "ssh", "mail", "www", "api", "dev", "test", "blog", "cms", "cdn", "db", "admin", "backup", "beta", "demo", "docs", "download", "forum", "help", "intranet", "jobs", "lab", "live", "login", "m", "mobile", "monitor", "news", "old", "partner", "pay", "payment", "portal", "preview", "prod", "production", "qa", "secure", "shop", "site", "staging", "static", "status", "support", "survey", "sys", "test2", "training", "uat", "upload", "user", "vpn", "web", "wiki", "wp", "www2", "www3", "www4", "archive", "assets", "auth", "billing", "cache", "calendar", "client", "cloud", "console", "content", "crm", "data", "database", "developer", "direct", "dns", "email", "files", "git", "host", "image", "images", "inbox", "info", "internal", "irc", "labs", "lists", "local", "log", "logs", "media", "metrics", "mirror", "network", "office", "online", "order", "panel", "photo", "photos", "podcast", "pop", "pop3", "private", "proxy", "public", "remote", "report", "res", "resource", "rss", "sandbox", "search", "secure2", "service", "smtp", "sso", "store", "stream", "subdomain", "sync", "system", "team", "temp", "tmp", "tracker", "updates", "video", "vps", "webmail", "widget", "app", "chat", "clientarea", "cloudfront", "community", "control", "customer", "dashboard", "developers", "discuss", "documentation", "downloads", "en", "es", "eu", "forums", "gateway", "github", "gitlab", "graph", "graphs", "groups", "home", "kb", "knowledgebase", "learn", "legal", "license", "licenses", "logout", "mail2", "mail3", "mail4", "mail5", "manager", "marketing", "members", "messages", "my", "newsletter", "newsletters", "orders", "org", "organizations", "password", "payments", "people", "press", "product", "products", "profile", "profiles", "project", "projects", "promo", "purchase", "purchases", "register", "registration", "reports", "rest", "restapi", "review", "reviews", "sales", "security", "services", "settings", "shopping", "sign", "signin", "signout", "signup", "sitemap", "ssl", "stage", "technology", "testing", "tickets", "tools", "trial", "try", "users", "videos", "view", "views", "wordpress", "work", "works", "worksheets", "xml", "xmpp", "xhr", "yaml", "yml", "you", "your", "youtube", "zabbix", "zen", "zip", "zoom", "zoho", "zscaler", "zimbra", "account", "administer", "affiliate", "alpha", "analytics", "appstore", "apps", "application", "applications", "art", "article", "articles", "asana", "authentication", "authorize", "backend", "bill", "board", "boards", "careers", "catalog", "checkout", "clients", "code", "coding", "company", "config", "configuration", "connect", "contact", "contacts", "core", "doc", "dropbox", "event", "events", "facebook", "faq", "faqs", "feed", "feeds", "file", "finance", "find", "finder", "firewall", "free", "frontend", "gallery", "games", "get", "google", "graphics", "guide", "guides", "hr", "hub", "humanresources", "idea", "ideas", "import", "information", "insights", "instagram", "internet", "io", "issue", "issues", "it", "job", "join", "journal", "journals", "knowledge", "language", "languages", "learning", "library", "libraries", "life", "link", "links", "list", "location", "locations", "maintenance", "map", "maps", "market", "markets", "member", "metrics", "messenger", "method", "methods", "model", "models", "module", "modules", "motion", "move", "music", "note", "notes", "notification", "notifications", "oauth", "offer", "offers", "open", "opensource", "organization", "outlook", "page", "pages", "place", "places", "platform", "plugin", "plugins", "poll", "polls", "post", "posts", "privacy", "promotions", "proof", "proofs", "pulse", "qa", "question", "questions", "quiz", "quizzes", "radio", "read", "reader", "reading", "release", "releases", "roadmap", "room", "rooms", "schedule", "school", "science", "sdk", "session", "sessions", "share", "sharepoint", "shopping", "show", "shows", "site", "sites", "skill", "skills", "slack", "slide", "slides", "solution", "solutions", "source", "sources", "space", "spaces", "spec", "specs", "speed", "speedtest", "spreadsheets", "start", "stories", "story", "sync", "table", "tables", "talk", "talking", "task", "tasks", "team", "teams", "template", "templates", "thread", "threads", "time", "timeline", "tool", "topic", "topics", "track", "tracking", "train", "translate", "translation", "tree", "trees", "trello", "tweet", "tweets", "twitter", "update", "upload", "uploads", "voice", "volume", "vote", "votes", "watch", "watches", "webinar", "webinars", "welcome", "widgets", "win", "windows", "wireframe", "wireframes", "workbench", "workflow", "workflows", "workspace", "workspaces", "write", "writes", "writer", "writers", "xbox", "xcode", "xerox", "xpath", "xray", "xtreme", "youtubers", "zone", "zones", "zoo", "zoos", "zurich", "zzz"
];
                    $results = [];
                    $domain = $_POST["nslookup_domain"];
                    foreach ($subdomains as $sub) {
                        $fullDomain = $sub . '.' . $domain;
                        try {
                            
                            $output = shell_exec("nslookup -query=ALL " . escapeshellarg($fullDomain));
                            
                            if (strpos($output, "NXDOMAIN") === false && strpos($output, "SERVFAIL") === false) {
                               
                                $filteredOutput = filterNslookupOutput($output);
                                if (!empty(trim($filteredOutput))) {
                                    $results[] = "<b>$fullDomain найден:</b><br><pre>" . htmlspecialchars($filteredOutput) . "</pre>";
                                }
                            }
                           
                        } catch (Exception $e) {
                            
                        }
                    }
                    
                    if (!empty($results)) {
                        echo implode("<br><br>", $results);
                    } else {
                        echo "<p>Ничего не найдено.</p>";
                    }
                    ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

   
    <div class="container">
        <div class="card">
            <h2 style="color:black;" >WhatWeb Scan</h2>
           
            <form method="POST" action="">
                <div class="form-group">
                    <label style="color:black;" for="whatweb_domain">Enter Domain:</label>
                    <input type="text" id="whatweb_domain" name="whatweb_domain" placeholder="example.com" required>
                </div>
                <div class="buttons-container">
                    <button type="submit" name="whatweb_scan" class="what-button">Start Scan</button>
                </div>
            </form>

            
            <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['whatweb_scan'])): ?>
                <div class="results" id="whatweb_results">
                    <button class="copy-button" onclick="copyWhatwebResults()">Copy to Clipboard</button>
                    <h2 style="color:black;" >WhatWeb Results:</h2>
                    <?php
                    $whatweb_domain = $_POST["whatweb_domain"];
                    try {
                       
                        $output = shell_exec("whatweb " . escapeshellarg($whatweb_domain));
                        if (!empty(trim($output))) {
                            echo "<pre style='white-space: pre-wrap;'>" . htmlspecialchars($output) . "</pre>";
                        } else {
                            echo "<p>Ничего не найдено.</p>";
                        }
                    } catch (Exception $e) {
                       
                    }
                    ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    
<div class="container">
    <div class="card">
        <h2 style="color:black;">WaybackUrls Scan</h2>
        
        <form method="POST" action="">
            <div class="form-group">
                <label style="color:black;" for="wayback_domain">Enter Domain:</label>
                <input type="text" id="wayback_domain" name="wayback_domain" placeholder="https://example.com" required>
            </div>
            <div class="buttons-container">
                <button type="submit" name="wayback_scan" class="wayback-button">Start Scan</button>
            </div>
        </form>
       
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['wayback_scan'])): ?>
            <div class="results" id="wayback_results">
                <button class="copy-button" onclick="copyWaybackResults()">Copy to Clipboard</button>
                <h2 style="color:black;">WaybackUrls Results:</h2>
                <?php
                function getWaybackUrls($domain) {
                    $wayback_url = "https://web.archive.org/cdx/search/cdx?url={$domain}/*&output=json&fl=original&collapse=urlkey";
                    $response = file_get_contents($wayback_url);
                    $urls = json_decode($response, true);
                    return $urls;
                }

                $wayback_domain = $_POST["wayback_domain"];
                $wayback_urls = getWaybackUrls($wayback_domain);

                if (!empty($wayback_urls)) {
                    echo "<ul>";
                    foreach ($wayback_urls as $url) {
                        echo "<li><a href='" . htmlspecialchars($url[0]) . "' target='_blank'>" . htmlspecialchars($url[0]) . "</a></li>";
                    }
                    echo "</ul>";
                } else {
                    echo "<p>No URLs found.</p>";
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</div>
    
    
    
<div class="container">
    <div class="card">
        <h2 style="color:black;" >Directory Check</h2>
        
        <form method="POST" action="">
            <div class="form-group">
                <label style="color:black;" for="directory_domain">Enter Domain:</label>
                <input type="text" id="directory_domain" name="directory_domain" placeholder="https://example.com" required>
            </div>
            <div class="buttons-container">
                <button type="submit" name="directory_check" class="directory-button">Start Scan</button>
            </div>
        </form>
       
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['directory_check'])): ?>
            <div class="results" id="directory_results">
                <button class="copy-button" onclick="copyDirectoryResults()">Copy to Clipboard</button>
                <h2 style="color:black;" >Directory Check Results:</h2>
                <?php
                
                $subdirectories = [
                    "/sub",
                    "/payment",
                    "/price",
                    "/about",
                    "/contact",
                    "/blog",
                    "/shop",
                    "/cart",
                    "/checkout",
                    "/login",
                    "/register",
                    "/robots.txt",
                    "/admin",
    "/admin.php",
    "/administrator",
    "/administrator.php",
    "/admin/login",
    "/admin/dashboard",
    "/admin/settings",
    "/admin/users",
    "/admin/panel",
    "/admin_area",
    "/admin_console",
    "/admin_login",
    "/dashboard",
    "/control",
    "/controlpanel",
    "/cpanel",
    "/moderator",
    "/root",
    "/superadmin",
    "/system",
    "/system_admin",
    "/secure",
    "/secure_admin",
    "/manage",
    "/management",
    "/login",
    "/login.php",
    "/auth",
    "/auth.php",
    "/signin",
    "/signup",
    "/register",
    "/logout",
    "/password_reset",
    "/forgot-password",
    "/account",
    "/accounts",
    "/user",
    "/users",
    "/profile",
    "/members",
    "/clients",
    "/customer",
    "/customers",
    "/config",
    "/config.php",
    "/config.inc.php",
    "/configuration.php",
    "/.env",
    "/settings",
    "/setup",
    "/setup.php",
    "/install",
    "/install.php",
    "/upgrade",
    "/update",
    "/database",
    "/database.php",
    "/db",
    "/dbadmin",
    "/dbadmin.php",
    "/phpmyadmin",
    "/phpmyadmin.php",
    "/mysql",
    "/mysql.php",
    "/sql",
    "/sql.php",
    "/db_backup",
    "/backup",
    "/backup.sql",
    "/dump.sql",
    "/wp-admin",
    "/wp-login.php",
    "/wp-content",
    "/wp-includes",
    "/wp-config.php",
    "/wp-json",
    "/wp-cron.php",
    "/wp-uploads",
    "/joomla",
    "/joomla-admin",
    "/drupal",
    "/magento",
    "/prestashop",
    "/logs",
    "/logs.php",
    "/log",
    "/error",
    "/error.php",
    "/errors",
    "/debug",
    "/debug.php",
    "/server-status",
    "/server-info",
    "/crash",
    "/stacktrace",
    "/cgi-bin",
    "/cgi-bin/test.cgi",
    "/cgi-bin/admin.cgi",
    "/cgi-bin/login.cgi",
    "/shell",
    "/shell.php",
    "/cmd",
    "/cmd.php",
    "/console",
    "/console.php",
    "/terminal",
    "/bash",
    "/bash.php",
    "/sh",
    "/sh.php",
    "/old",
    "/old_site",
    "/backup_old",
    "/backups",
    "/bak",
    "/bak.php",
    "/site_old",
    "/archive",
    "/archives",
    "/admin_old",
    "/admin_bak",
    "/db_old",
    "/database_old",
    "/config_old",
    "/api",
    "/api.php",
    "/graphql",
    "/graphql.php",
    "/mail",
    "/mail.php",
    "/webmail",
    "/email",
    "/newsletter",
    "/subscribe",
    "/unsubscribe",
    "/sms",
    "/webhook",
    "/json",
    "/xml",
    "/shop",
    "/store",
    "/cart",
    "/checkout",
    "/payment",
    "/pay",
    "/order",
    "/orders",
    "/invoice",
    "/billing",
    "/shipping",
    "/track",
    "/tracking",
    "/uploads",
    "/upload",
    "/files",
    "/file",
    "/documents",
    "/docs",
    "/downloads",
    "/download",
    "/gallery",
    "/images",
    "/img",
    "/media",
    "/music",
    "/videos",
    "/video",
    "/audio",
    "/static",
    "/assets",
    "/css",
    "/js",
    "/fonts",
    "/themes",
    "/templates",
    "/vendor",
    "/modules",
    "/components",
    "/includes",
    "/lib",
    "/libs",
    "/source",
    "/sources",
    "/robots.txt",
    "/sitemap.xml",
    "/ads.txt",
    "/humans.txt",
    "/security.txt",
    "/privacy-policy",
    "/terms",
    "/terms-of-service",
    "/tos",
    "/legal",
    "/license",
    "/cookies",
    "/index.php",
    "/index.html",
    "/home",
    "/about",
    "/about-us",
    "/contact",
    "/contact-us",
    "/support",
    "/help",
    "/faq",
    "/blog",
    "/news",
    "/rss",
    "/press",
    "/events",
    "/private",
    "/restricted",
    "/confidential",
    "/hidden",
    "/secret",
    "/vault",
    "/keys",
    "/key",
    "/security",
    "/security_check",
    "/admin_secret",
    "/beta",
    "/test",
    "/staging",
    "/demo",
    "/status",
    "/status.php",
    "/health",
    "/monitoring",
    "/ping",
    "/diagnostics",
     
 ];

                
                function checkDirectory($domain, $directory) {
                    $url = $domain . $directory;
                    $headers = @get_headers($url);

                    if ($headers && strpos($headers[0], '200') !== false) {
                        return true;
                    } else {
                        return false;
                    }
                }

                
                $domain = $_POST['directory_domain'];

echo "<h2 style='color: black;'>Поиск Директорий на {$domain}</h2>";

                
                foreach ($subdirectories as $directory) {
                    $exists = checkDirectory($domain, $directory);
                    if ($exists) {
                        echo "<p><strong>{$directory}</strong> &nbsp;| найдено </p>";
                    } else {
                        
                    }
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</div>
    
    
    
    <div class="container">
    <div class="card">
        <h2 style="color:black;">Port Scan</h2>
       
        <form method="POST" action="">
            <div class="form-group">
                <label style="color:black;" for="nmap_host">Enter Host:</label>
                <input type="text" id="nmap_host" name="nmap_host" placeholder="example.com or IP address" required>
            </div>
            <div class="buttons-container">
                <button type="submit" name="nmap_scan" class="nmap-button">Start Scan</button>
            </div>
        </form>
      
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['nmap_scan'])): ?>
            <div class="results" id="nmap_results">
                <button class="copy-button" onclick="copyNmapResults()">Copy to Clipboard</button>
                <h2 style="color:black;" >Nmap Results:</h2>
                <?php
                
                $host = escapeshellarg($_POST['nmap_host']); 

                echo "<h2>Scanning host: {$host}</h2>";

               
                $nmap_path = shell_exec('which nmap');
                if (empty(trim($nmap_path))) {
                    echo "<p>Error: Nmap is not installed or not accessible.</p>";
                } else {
                   
                    $command = "nmap -sV -A -Pn {$host} 2>&1"; 
                    $output = shell_exec($command);

                    if ($output) {
                        echo "<pre>" . htmlspecialchars($output) . "</pre>";
                    } else {
                        echo "<p>Error: Unable to execute Nmap or no results found.</p>";
                    }

                   
                    error_log("Command executed: $command");
                    error_log("Output: $output");
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<div class="container">
    <div class="card">
        <h2 style="color:black;" >WAF Detection</h2>
       
        <form method="POST" action="">
            <div class="form-group">
                <label style="color:black;" for="waf_url">Enter URL or IP:</label>
                <input type="text" id="waf_url" name="waf_url" placeholder="https://example.com" required>
            </div>
            <div class="buttons-container">
                <button type="submit" name="waf_check" class="waf-button">Start Scan</button>
            </div>
        </form>
        
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['waf_check'])): ?>
            <div class="results" id="waf_results">
                <button class="copy-button" onclick="copyWafResults()">Copy to Clipboard</button>
                <h2>WAF Check Results:</h2>
                <?php
              
                $url = escapeshellarg($_POST['waf_url']); 

                echo "<h3>Checking for WAF on {$url}</h3>";

               
                $wafw00f_path = shell_exec('which wafw00f');
                if (empty(trim($wafw00f_path))) {
                    echo "<p>Error: wafw00f is not installed or not accessible.</p>";
                } else {
                    
                    $command = "wafw00f {$url} 2>&1"; 
                    $output = shell_exec($command);

                    if ($output) {
                       
                        $filtered_output = '';
                        $lines = explode("\n", $output); 
                        foreach ($lines as $line) {
                           
                            if (
                                preg_match('/^\[.*\]/', $line) || 
                                preg_match('/^[-+].*:/i', $line) || 
                                preg_match('/^Number of requests: \d+/', $line) 
                            ) {
                                $filtered_output .= trim($line) . "\n"; 
                            }
                        }

                        if (!empty($filtered_output)) {
                            echo "<pre>" . htmlspecialchars(trim($filtered_output)) . "</pre>";
                        } else {
                            echo "<p>No technical information found in the output.</p>";
                        }
                    } else {
                        echo "<p>Error: Unable to execute wafw00f or no results found.</p>";
                    }

                    
                    error_log("Command executed: $command");
                    error_log("Output: $output");
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</div>
    

<div class="container">
    <div class="card">
        <h2 style="color:black;">API Endpoint Finder</h2>
        
        <form method="POST" action="">
            <div class="form-group">
                <label style="color:black;" for="api_domain">Enter Domain:</label>
                <input type="text" id="api_domain" name="api_domain" placeholder="https://example.com" required>
            </div>
            <div class="buttons-container">
                <button type="submit" name="api_check" class="api-button">Start Scan</button>
            </div>
        </form>
       
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['api_check'])): ?>
            <div class="results" id="api_results">
                <button class="copy-button" onclick="copyApiResults()">Copy to Clipboard</button>
                <h2 style="color:black;">API Endpoint Check Results:</h2>
                <?php
                
                
                $api_endpoints = [
                       "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/graphql/schema",
    "/graphql/playground",
    "/graphql/query",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/rest/v3",
    "/rest/auth",
    "/rest/users",
    "/rest/posts",
    "/rest/orders",
    "/rest/products",
    "/rest/settings",
    "/rest/system",
    "/wp-json",
    "/wp-json/wp/v1",
    "/wp-json/wp/v2",
    "/wp-json/wp/v3",
    "/wp-json/oembed",
    "/wp-json/jwt-auth/v1/token",
    "/wp-json/contact-form-7/v1",
    "/wp-json/wc/v3",
    "/wp-json/wc/v2",
    "/wp-json/acf/v3",
    "/wp-json/yoast/v1",
    "/wp-json/wpml/v1",
    "/wp-json/litespeed/v1",
    "/joomla/api",
    "/joomla/rest",
    "/joomla/v1",
    "/joomla/v2",
    "/joomla/users",
    "/joomla/articles",
    "/joomla/categories",
    "/joomla/contacts",
    "/joomla/tags",
    "/joomla/menu",
    "/joomla/modules",
    "/joomla/templates",
    "/joomla/plugins",
    "/opencart/api",
    "/opencart/rest",
    "/opencart/v1",
    "/opencart/v2",
    "/opencart/products",
    "/opencart/categories",
    "/opencart/customers",
    "/opencart/orders",
    "/opencart/coupons",
    "/opencart/payments",
    "/opencart/shipping",
    "/opencart/stats",
    "/prestashop/api",
    "/prestashop/rest",
    "/prestashop/v1",
    "/prestashop/v2",
    "/prestashop/products",
    "/prestashop/customers",
    "/prestashop/orders",
    "/prestashop/cart",
    "/prestashop/categories",
    "/prestashop/manufacturers",
    "/prestashop/stock",
    "/prestashop/addresses",
    "/prestashop/shipping",
    "/prestashop/returns",
    "/maltego/api",
    "/maltego/rest",
    "/maltego/v1",
    "/maltego/v2",
    "/maltego/transform",
    "/maltego/graph",
    "/maltego/entities",
    "/maltego/settings",
    "/auth",
    "/auth/token",
    "/auth/login",
    "/auth/logout",
    "/auth/refresh",
    "/auth/validate",
    "/oauth",
    "/oauth2",
    "/oauth/token",
    "/oauth/authorize",
    "/jwt",
    "/jwt/token",
    "/jwt/verify",
    "/users",
    "/users/v1",
    "/users/v2",
    "/users/me",
    "/users/profile",
    "/users/settings",
    "/users/roles",
    "/users/permissions",
    "/users/notifications",
    "/users/activity",
    "/admin",
    "/admin/api",
    "/admin/settings",
    "/admin/logs",
    "/admin/analytics",
    "/admin/monitoring",
    "/admin/system",
    "/admin/backup",
    "/admin/reports",
    "/orders",
    "/orders/v1",
    "/orders/v2",
    "/orders/status",
    "/orders/details",
    "/orders/history",
    "/orders/cancel",
    "/orders/refund",
    "/payments",
    "/payments/v1",
    "/payments/v2",
    "/payments/gateway",
    "/payments/stripe",
    "/payments/paypal",
    "/payments/bitcoin",
    "/payments/transactions",
    "/shop",
    "/shop/api",
    "/shop/products",
    "/shop/cart",
    "/shop/checkout",
    "/shop/orders",
    "/shop/customers",
    "/shop/coupons",
    "/shop/reviews",
    "/shop/stock",
    "/inventory",
    "/inventory/stock",
    "/inventory/products",
    "/inventory/reports",
    "/support",
    "/support/tickets",
    "/support/chat",
    "/support/faq",
    "/support/docs",
    "/support/feedback",
    "/blog",
    "/blog/api",
    "/blog/posts",
    "/blog/categories",
    "/blog/comments",
    "/blog/tags",
    "/blog/recent",
    "/notifications",
    "/notifications/list",
    "/notifications/unread",
    "/notifications/read",
    "/notifications/settings",
    "/settings",
    "/settings/general",
    "/settings/security",
    "/settings/privacy",
    "/settings/api-keys",
    "/settings/integrations",
    "/analytics",
    "/analytics/v1",
    "/analytics/v2",
    "/analytics/traffic",
    "/analytics/sales",
    "/analytics/events",
    "/analytics/reports",
    "/reports",
    "/reports/v1",
    "/reports/v2",
    "/reports/sales",
    "/reports/users",
    "/reports/security",
    "/integrations",
    "/integrations/list",
    "/integrations/connect",
    "/integrations/disconnect",
    "/integrations/status",
    "/integrations/settings",
    "/cms",
    "/cms/api",
    "/cms/pages",
    "/cms/blocks",
    "/cms/media",
    "/cms/settings",
    "/wordpress",
    "/wp-json/wp/v1/plugins",
    "/wp-json/wp/v1/themes",
    "/wp-json/wp/v1/users",
    "/wp-json/wp/v1/media",
    "/wp-json/wp/v1/settings",
    "/magento",
    "/magento/api",
    "/magento/rest",
    "/magento/v1",
    "/magento/v2",
    "/magento/products",
    "/magento/customers",
    "/magento/orders",
    "/magento/cart",
    "/magento/shipping",
    "/magento/stock",
    "/magento/pricing",
    "/magento/coupons",
    "/magento/returns",
    "/drupal",
    "/drupal/api",
    "/drupal/v1",
    "/drupal/v2",
    "/drupal/content",
    "/drupal/users",
    "/drupal/comments",
    "/drupal/taxonomy",
    "/drupal/views",
    "/drupal/files",
    "/drupal/config",
    "/drupal/cache",
    "/drupal/performance",
    "/drupal/modules",
    "/typo3",
    "/typo3/api",
    "/typo3/rest",
    "/typo3/v1",
    "/typo3/v2",
    "/typo3/pages",
    "/typo3/content",
    "/typo3/media",
    "/typo3/settings",
    "/typo3/extensions",
    "/typo3/cache",
    "/typo3/themes",
    "/typo3/seo",
    "/typo3/backup",
    "/typo3/roles",
    "/typo3/permissions",
    "/api/random",
    "/api/proxy",
    "/api/ip",
    "/api/geoip",
    "/api/timezone",
    "/api/qrcode",
    "/api/barcode",
    "/api/image",
    "/api/video",
    "/api/music",
    "/api/stream",
    "/api/gateway",
    "/api/messages",
    "/api/comments",
    "/api/likes",
    "/api/friends",
    "/api/followers",
    "/api/chat",
    "/api/captcha",
    "/api/cdn",
    "/api/sync",
    "/api/backup",
    "/api/recovery",
    "/api/security",
    "/api/antifraud",
    "/api/encryption",
    "/api/blocklist",
    "/api/allowlist",
    "/api/spam",
    "/api/logs",
    "/api/dns",
    "/api/network",
    "/api/firewall"
                ];

                
                function checkApiEndpoint($domain, $endpoint) {
                    $url = $domain . $endpoint;
                    $headers = @get_headers($url);
                    if ($headers && strpos($headers[0], '200') !== false) {
                        return true;
                    } else {
                        return false;
                    }
                }

                
                $domain = $_POST['api_domain'];
echo "<h2 style='color: black;'>Поиск Api на {$domain}</h2>";

                
                $foundEndpoints = [];
                foreach ($api_endpoints as $endpoint) {
                    if (checkApiEndpoint($domain, $endpoint)) {
                        $foundEndpoints[] = $endpoint;
                    }
                }

                
                if (!empty($foundEndpoints)) {
                    foreach ($foundEndpoints as $endpoint) {
                        echo "<p><strong>{$endpoint}</strong> &nbsp;| найдено </p>";
                    }
                } else {
                    echo "<p> Ничего не найдено.</p>";
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</div>
    
    
    
    <div class="container">
    <div class="card">
        <h2 style="color:black;">SSL Certificate Check</h2>
        
        <form method="POST" action="">
            <div class="form-group">
                <label style="color:black;" for="ssl_domain">Enter Domain:</label>
                <input type="text" id="ssl_domain" name="ssl_domain" placeholder="https://example.com" required>
            </div>
            <div class="buttons-container">
                <button type="submit" name="ssl_check" class="ssl-button">Check SSL Certificate</button>
            </div>
        </form>
       
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['ssl_check'])): ?>
            <div class="results" id="ssl_results">
                <button class="copy-button" onclick="copySslResults()">Copy to Clipboard</button>
                <h2 style="color:black;">SSL Certificate Results:</h2>
                <?php
                function checkSslCertificate($domain) {
                    $parsed_url = parse_url($domain);
                    $host = $parsed_url['host'];
                    $port = isset($parsed_url['port']) ? $parsed_url['port'] : 443;

                    $context = stream_context_create([
                        "ssl" => [
                            "capture_peer_cert" => true,
                        ],
                    ]);

                    $fp = @stream_socket_client("ssl://" . $host . ":" . $port, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

                    if (!$fp) {
                        return "Error: Unable to connect to the server.";
                    }

                    $cert = stream_context_get_params($fp)['options']['ssl']['peer_certificate'];
                    fclose($fp);

                    $cert_info = openssl_x509_parse($cert);
                    return $cert_info;
                }

                $ssl_domain = $_POST["ssl_domain"];
                $ssl_info = checkSslCertificate($ssl_domain);

                if (is_array($ssl_info)) {
                    echo "<pre>";
                    print_r($ssl_info);
                    echo "</pre>";
                } else {
                    echo "<p>" . htmlspecialchars($ssl_info) . "</p>";
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</div>
    
   
   <div class="container">
    <div class="card">
        <h2 style="color:black;">WHOIS Scan</h2>
        
        <form method="POST" action="">
            <div class="form-group">
                <label style="color:black;" for="whois_domain">Enter Domain:</label>
                <input type="text" id="whois_domain" name="whois_domain" placeholder="example.com" required>
            </div>
            <div class="buttons-container">
                <button type="submit" name="whois_check" class="whois-button">Check WHOIS</button>
            </div>
        </form>
       
        <?php if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['whois_check'])): ?>
            <div class="results" id="whois_results">
                <button class="copy-button" onclick="copyWhoisResults()">Copy to Clipboard</button>
                <h2 style="color:black;">WHOIS Results:</h2>
                <?php
                function getWhoisInfo($domain) {
                    $whois = shell_exec("whois {$domain}");
                    return $whois;
                }

                $whois_domain = $_POST["whois_domain"];
                $whois_info = getWhoisInfo($whois_domain);

                if (!empty(trim($whois_info))) {
                    echo "<pre>" . htmlspecialchars($whois_info) . "</pre>";
                } else {
                    echo "<p>No WHOIS information found.</p>";
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</div>

   
    
    
    <script>
        function copyToClipboard() {
            const resultsElement = document.getElementById('results');
            const range = document.createRange();
            range.selectNode(resultsElement);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            document.execCommand('copy');
            window.getSelection().removeAllRanges();
            alert('Results copied to clipboard!');
        }

        function copyWhatwebResults() {
            const whatwebResultsElement = document.getElementById('whatweb_results');
            const range = document.createRange();
            range.selectNode(whatwebResultsElement);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            document.execCommand('copy');
            window.getSelection().removeAllRanges();
            alert('WhatWeb results copied to clipboard!');
        }

   function copyWaybackResults() {
        var results = document.getElementById('wayback_results').innerText;
        navigator.clipboard.writeText(results).then(function() {
        }, function(err) {
            console.error('Не удалось скопировать текст: ', err);
        });
    }
        
            function copyDirectoryResults() {
        var results = document.getElementById('directory_results').innerText;
        navigator.clipboard.writeText(results).then(function() {
        }, function(err) {
            console.error('Не удалось скопировать текст: ', err);
        });
    }
    
        function copyNmapResults() {
        var results = document.getElementById('nmap_results').innerText;
        navigator.clipboard.writeText(results).then(function() {
        }, function(err) {
            console.error('Не удалось скопировать текст: ', err);
        });
    }
        
            function copyWafResults() {
        var results = document.getElementById('waf_results').innerText;
        navigator.clipboard.writeText(results).then(function() {
        }, function(err) {
            console.error('Не удалось скопировать текст: ', err);
        });
    }
        
function copyApiResults() {
        var results = document.getElementById('api_results').innerText;
        navigator.clipboard.writeText(results).then(function() {
        }, function(err) {
            console.error('Не удалось скопировать текст: ', err);
        });
    } 
    
        function copySslResults() {
        var results = document.getElementById('ssl_results').innerText;
        navigator.clipboard.writeText(results).then(function() {
        }, function(err) {
            console.error('Не удалось скопировать текст: ', err);
        });
    }
    
    
        function copyWhoisResults() {
        var results = document.getElementById('whois_results').innerText;
        navigator.clipboard.writeText(results).then(function() {
        }, function(err) {
            console.error('Не удалось скопировать текст: ', err);
        });
    }
    
    </script>
</body>
</html>

<?php

function filterNslookupOutput($output) {
   
    $removeLines = [
        'unknown query type: ALL',
        'Server:',
        'Non-authoritative answer:'
    ];
   
    $lines = explode("\n", $output);
   
    $filteredLines = array_filter($lines, function($line) use ($removeLines) {
        foreach ($removeLines as $removeLine) {
            if (strpos($line, $removeLine) !== false) {
                return false;
            }
        }
        return true;
    });

    return trim(implode("\n", $filteredLines));
}
?>
