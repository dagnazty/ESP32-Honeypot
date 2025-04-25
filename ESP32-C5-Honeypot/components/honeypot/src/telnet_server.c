#include "telnet_server.h"
#include "file_system.h"
#include "config.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/err.h"
#include "esp_http_client.h"
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#define TELNET_PORT 23
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
#define LARGE_BUFFER_SIZE 2048
#define RECV_TIMEOUT_SEC 5
#define MAX_CMD_LENGTH 256
#define MAX_LOG_LENGTH 512
#define MAX_WEBHOOK_LEN 256

// Telnet protocol commands
#define IAC     255  // Interpret As Command
#define DONT    254
#define DO      253
#define WONT    252
#define WILL    251
#define SB      250  // Subnegotiation Begin
#define SE      240  // Subnegotiation End

// Forward declarations
static void process_command(int client_socket, const char *cmd, struct sockaddr_in *client_addr);
static void safe_send(int socket, const char *data, size_t len);
static void log_client_command(const char *cmd, struct sockaddr_in *client_addr);
static void send_webhook_alert(const char *cmd, struct sockaddr_in *client_addr);

static const char *TAG = "TELNET";
static TaskHandle_t server_task_handle = NULL;
static int server_socket = -1;
static bool server_running = false;
static SemaphoreHandle_t client_mutex = NULL;

// Webhook task parameters
typedef struct {
    char url[MAX_WEBHOOK_LEN];
    char payload[512];
} webhook_params_t;

typedef struct {
    char command[MAX_CMD_LENGTH];
    struct sockaddr_in client_addr;
} command_message_t;

// Fake file system content
static const char *FAKE_ETC_PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
                                     "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                                     "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                                     "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                                     "sync:x:4:65534:sync:/bin:/bin/sync\n"
                                     "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
                                     "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
                                     "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
                                     "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
                                     "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
                                     "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
                                     "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
                                     "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                                     "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
                                     "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
                                     "irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\n"
                                     "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
                                     "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                                     "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
                                     "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
                                     "systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n"
                                     "messagebus:x:103:106::/nonexistent:/usr/sbin/nologin\n"
                                     "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
                                     "mysql:x:105:113:MySQL Server,,,:/var/lib/mysql:/bin/false\n"
                                     "admin:x:1000:1000:Server Admin:/home/admin:/bin/bash\n";

static const char *FAKE_SECRETS_TXT = "# Server passwords and private keys\n"
                                     "# IMPORTANT: Keep this file secure!\n"
                                     "\n"
                                     "MySQL root password: p@ssw0rd123\n"
                                     "Remote admin user: admin\n"
                                     "Remote admin password: Adm1n@Server\n"
                                     "\n"
                                     "# API Keys\n"
                                     "AWS_ACCESS_KEY=AKIA5HGFTYU78JKLMNOP\n"
                                     "AWS_SECRET_KEY=jK8Hgt5Frd3Sa1Qp9Xc8Vb7Nm2Kl6Oi4Uy5Tr7Ws\n"
                                     "\n"
                                     "# SSH Private Key (DO NOT SHARE)\n"
                                     "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                     "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
                                     "NhAAAAAwEAAQAAAYEAtHCsSzHtUF8m82bwGyT8RRsrlRhzLLFD7Z8mejkQR1x/3Qtp5CLV\n"
                                     "1YKgNfXZKB6dLJ1N0s1qXeaO5yEfGtx3UTBLuBRFvJnJ8R4ygN1WKVzjj1PhiKE3msqH9K\n"
                                     "-----END OPENSSH PRIVATE KEY-----\n";

static const char *FAKE_DB_CONFIG = "# Database configuration\n"
                                    "DB_HOST=localhost\n"
                                    "DB_PORT=3306\n"
                                    "DB_NAME=production_db\n"
                                    "DB_USER=admin\n"
                                    "DB_PASS=Adm1n@Server\n"
                                    "DB_BACKUP_PATH=/var/backups/mysql/\n"
                                    "DB_BACKUP_RETENTION=7\n";

// Additional fake files
static const char *FAKE_SSH_CONFIG = "# SSH Server Configuration File\n"
                                   "Port 22\n"
                                   "Protocol 2\n"
                                   "HostKey /etc/ssh/ssh_host_rsa_key\n"
                                   "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
                                   "HostKey /etc/ssh/ssh_host_ed25519_key\n"
                                   "UsePrivilegeSeparation yes\n"
                                   "KeyRegenerationInterval 3600\n"
                                   "ServerKeyBits 1024\n"
                                   "SyslogFacility AUTH\n"
                                   "LogLevel INFO\n"
                                   "LoginGraceTime 120\n"
                                   "PermitRootLogin prohibit-password\n"
                                   "StrictModes yes\n"
                                   "RSAAuthentication yes\n"
                                   "PubkeyAuthentication yes\n"
                                   "AuthorizedKeysFile %h/.ssh/authorized_keys\n"
                                   "IgnoreRhosts yes\n"
                                   "RhostsRSAAuthentication no\n"
                                   "HostbasedAuthentication no\n"
                                   "PermitEmptyPasswords no\n"
                                   "ChallengeResponseAuthentication no\n"
                                   "PasswordAuthentication yes\n"
                                   "X11Forwarding yes\n"
                                   "X11DisplayOffset 10\n"
                                   "PrintMotd no\n"
                                   "PrintLastLog yes\n"
                                   "TCPKeepAlive yes\n"
                                   "AcceptEnv LANG LC_*\n"
                                   "Subsystem sftp /usr/lib/openssh/sftp-server\n"
                                   "UsePAM yes\n";

static const char *FAKE_NGINX_CONFIG = "user www-data;\n"
                                     "worker_processes auto;\n"
                                     "pid /run/nginx.pid;\n"
                                     "include /etc/nginx/modules-enabled/*.conf;\n"
                                     "\n"
                                     "events {\n"
                                     "    worker_connections 768;\n"
                                     "}\n"
                                     "\n"
                                     "http {\n"
                                     "    server {\n"
                                     "        listen 80 default_server;\n"
                                     "        listen [::]:80 default_server;\n"
                                     "        root /var/www/html;\n"
                                     "        index index.html index.htm index.nginx-debian.html;\n"
                                     "        server_name _;\n"
                                     "        location / {\n"
                                     "            try_files $uri $uri/ =404;\n"
                                     "        }\n"
                                     "    }\n"
                                     "\n"
                                     "    server {\n"
                                     "        listen 443 ssl;\n"
                                     "        server_name example.com;\n"
                                     "        ssl_certificate /etc/nginx/ssl/example.com.crt;\n"
                                     "        ssl_certificate_key /etc/nginx/ssl/example.com.key;\n"
                                     "        ssl_protocols TLSv1.2 TLSv1.3;\n"
                                     "        ssl_ciphers HIGH:!aNULL:!MD5;\n"
                                     "        location / {\n"
                                     "            proxy_pass http://localhost:8080;\n"
                                     "        }\n"
                                     "    }\n"
                                     "}\n";

static const char *FAKE_SSH_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
                                "MIIEpAIBAAKCAQEAyLHhv6RKH0t4ij5zQ6MxMmolSXITiYkLUp7QTqV5Ed0bUZ0T\n"
                                "Esr8GLfPJgOI2KsFhM7JWCpiHoIcTTOiM3s57BOu0GxrfpTVGpOAwnhVIjE901xZ\n"
                                "MXQJNuvFrDtscNY+O4GYsZ9QGciHTGwjvK1bLfDcjBKvpKg3I2JHuE3WK2d09qV1\n"
                                "JIU+U0xS0Z/GJ3wj1YdJ1HGwnsyXRoHLSmXqIjIazLlG1CTHZH1yAYZt9tBK2ogj\n"
                                "OQOL3cCmx8G397Y1vvSRnpnVbgj6QHk5JRGLfae0z32koXnuoUAEh5XagL2KIwKH\n"
                                "d4u0w/vA9A+s8GU5H+PfQzfXJPD6R0KjESRwxQIDAQABAoIBAGOzxIfN74H6MN3L\n"
                                "MmhfhI7OQyVJBnXhd+48IZwcn5eqrwL0hAqHLZmBMyPnmLbF0CqO9m+i0QAQFsMl\n"
                                "Dv7nCvjEJGXDuGx4a2yG1vP4jUn/ZA/btPKXbIvJ2Z+KL9+MaRY3DWikV7CcC1Tf\n"
                                "bZ8XoGbCu7PiYbRRGZqAJuQJ3mDfHd7yu8WPz3lWMFCrLzwRybU6Kw9iBzRXKzDM\n"
                                "-----END RSA PRIVATE KEY-----\n";

static const char *FAKE_AWS_CREDENTIALS = "[default]\n"
                                        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                                        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                                        "region = us-west-2\n"
                                        "\n"
                                        "[production]\n"
                                        "aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n"
                                        "aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n"
                                        "region = us-east-1\n";

static const char *FAKE_ENV_FILE = "# Environment variables for application\n"
                                 "DB_HOST=localhost\n"
                                 "DB_USER=admin\n"
                                 "DB_PASS=LVkE3MjYZE4BVnGj8Qz93Kj2SxQFTUXR\n"
                                 "DB_NAME=production\n"
                                 "REDIS_HOST=redis.internal\n"
                                 "REDIS_PORT=6379\n"
                                 "API_KEY=sk_live_UQV9RvFfpQgIXVcPnJwAgmj7\n"
                                 "JWT_SECRET=3e367a60ddc0539c506c5b97904ce3c6d5f448b2f5ad6a29d4c3f1bcc345689f\n"
                                 "ADMIN_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.5vx_cBqIUXnUi1h6S2myjTuj_IBX92YvCDCZpkS_WQo\n";

static void safe_send(int socket, const char *data, size_t len) {
    if (socket < 0 || !data) return;
    
    size_t total_sent = 0;
    while (total_sent < len) {
        int sent = send(socket, data + total_sent, len - total_sent, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            ESP_LOGW(TAG, "Send failed: errno %d", errno);
            break;
        }
        total_sent += sent;
    }
}

/**
 * @brief Send a webhook alert about a command executed in the honeypot
 * 
 * @param cmd The command that was executed
 * @param client_addr The client address structure
 */
static void send_webhook_alert(const char *cmd, struct sockaddr_in *client_addr)
{
    // Get the webhook URL from config
    honeypot_config_t *config = config_get();
    
    if (!config->webhook_url[0]) {
        return; // No webhook configured
    }

    // Convert IP to string
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), ip_str, INET_ADDRSTRLEN);

    // Create Discord-style webhook payload
    char payload[512];
    snprintf(payload, sizeof(payload), 
        "{\"content\":\"📢 **Honeypot Alert**\\n🔍 IP: %s\\n💻 Command: `%s`\"}", 
        ip_str, cmd);

    // Log the payload we're sending
    ESP_LOGI(TAG, "Payload: %s", payload);

    // Prepare for URL parsing
    char url_buf[256];
    strlcpy(url_buf, config->webhook_url, sizeof(url_buf));
    
    // Allow up to 5 redirects
    int redirect_count = 0;
    const int max_redirects = 5;
    
    while (redirect_count < max_redirects) {
        // Parse URL components
        char *url = url_buf;
        char hostname[128] = {0};
        char path[256] = "/";
        int port = 80;
        bool is_https = false;
        
        // Check for protocol
        if (strncmp(url, "https://", 8) == 0) {
            is_https = true;
            port = 443;
            url += 8;
        } else if (strncmp(url, "http://", 7) == 0) {
            url += 7;
        }
        
        // Extract hostname and path
        char *path_start = strchr(url, '/');
        if (path_start) {
            size_t hostname_len = path_start - url;
            if (hostname_len >= sizeof(hostname)) {
                ESP_LOGE(TAG, "Hostname too long");
                return;
            }
            memcpy(hostname, url, hostname_len);
            hostname[hostname_len] = '\0';
            strlcpy(path, path_start, sizeof(path));
        } else {
            strlcpy(hostname, url, sizeof(hostname));
        }
        
        // Check if hostname includes port
        char *port_str = strchr(hostname, ':');
        if (port_str) {
            *port_str = '\0';
            port = atoi(port_str + 1);
        }

        // If it's HTTPS, we need to convert to HTTP for our simple client
        if (is_https) {
            ESP_LOGI(TAG, "Converting HTTPS URL to HTTP for Discord webhook");
            // We're expecting this to be handled by a proxy or redirect
        }
        
        ESP_LOGI(TAG, "Connecting to Host: %s, Path: %s, Port: %d", hostname, path, port);
        
        // DNS lookup
        struct hostent* he = gethostbyname(hostname);
        if (!he) {
            ESP_LOGE(TAG, "DNS lookup failed for host: %s", hostname);
            return;
        }
        
        // Create socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            ESP_LOGE(TAG, "Failed to create socket");
            return;
        }
        
        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        // Connect
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr = *((struct in_addr*)he->h_addr);
        server_addr.sin_port = htons(port);
        
        ESP_LOGI(TAG, "Connecting to IP: %s", inet_ntoa(server_addr.sin_addr));
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) < 0) {
            ESP_LOGE(TAG, "Socket connect failed: %d", errno);
            close(sock);
            return;
        }
        
        // Format HTTP request (POST with JSON content)
        char http_request[1024];
        snprintf(http_request, sizeof(http_request),
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: ESP32-Honeypot/1.0\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            path, hostname, strlen(payload), payload);
        
        ESP_LOGI(TAG, "Sending HTTP request (%d bytes)", strlen(http_request));
        
        // Send request
        if (send(sock, http_request, strlen(http_request), 0) < 0) {
            ESP_LOGE(TAG, "Send failed: %d", errno);
            close(sock);
            return;
        }
        
        // Receive response to check for redirects
        char response_buf[1024] = {0};
        int bytes_received = recv(sock, response_buf, sizeof(response_buf) - 1, 0);
        
        close(sock); // Close the socket as we're done with this connection
        
        if (bytes_received <= 0) {
            ESP_LOGE(TAG, "Failed to receive response");
            return;
        }
        
        response_buf[bytes_received] = '\0';
        
        // Log the response status line
        char *newline = strchr(response_buf, '\n');
        if (newline) {
            *newline = '\0';
            ESP_LOGI(TAG, "Response: %s", response_buf);
            *newline = '\n'; // Restore newline for further processing
        }
        
        // Check for redirect (HTTP 301/302/307/308)
        if (strstr(response_buf, "HTTP/1.1 301") || 
            strstr(response_buf, "HTTP/1.1 302") ||
            strstr(response_buf, "HTTP/1.1 307") ||
            strstr(response_buf, "HTTP/1.1 308")) {
            
            ESP_LOGI(TAG, "Redirect detected");
            
            // Extract Location header
            char *location = strstr(response_buf, "Location:");
            if (!location) {
                location = strstr(response_buf, "location:");
            }
            
            if (location) {
                location += 9; // Skip "Location:"
                
                // Skip whitespace
                while (*location == ' ' || *location == '\t') {
                    location++;
                }
                
                // Extract the URL (until newline)
                char *end = strchr(location, '\r');
                if (!end) {
                    end = strchr(location, '\n');
                }
                
                if (end) {
                    size_t url_len = end - location;
                    if (url_len < sizeof(url_buf)) {
                        memcpy(url_buf, location, url_len);
                        url_buf[url_len] = '\0';
                        
                        ESP_LOGI(TAG, "Following redirect to: %s", url_buf);
                        redirect_count++;
                        continue; // Follow the redirect
                    } else {
                        ESP_LOGE(TAG, "Redirect URL too long");
                    }
                }
            }
        }
        
        // If we get here, either got a success response or failed to extract the redirect
        ESP_LOGI(TAG, "Webhook request completed (redirect count: %d)", redirect_count);
        return;
    }
    
    ESP_LOGW(TAG, "Too many redirects (%d)", redirect_count);
}

static void log_client_command(const char *cmd, struct sockaddr_in *client_addr)
{
    // Skip if invalid parameters
    if (!cmd || !client_addr) {
        return;
    }
    
    // Just log the command
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(client_addr->sin_addr), ip_str, INET_ADDRSTRLEN) != NULL) {
        ESP_LOGI(TAG, "Command received: '%s' from IP: %s", cmd, ip_str);
    }
    
    // Send webhook alert
    send_webhook_alert(cmd, client_addr);
}

/**
 * Sanitize a command string, replacing control and non-ASCII characters
 * with safe representations to prevent log injection and display issues.
 * 
 * @param dest The destination buffer
 * @param src The source string
 * @param max_len Maximum length of the destination buffer
 * @return The length of the sanitized string
 */
static int sanitize_command(char *dest, const char *src, size_t max_len) {
    if (!dest || !src || max_len == 0) {
        return 0;
    }
    
    int dest_pos = 0;
    
    for (int i = 0; src[i] != '\0' && dest_pos < max_len - 1; i++) {
        unsigned char c = (unsigned char)src[i];
        
        // Control characters (including CR/LF)
        if (c < 32 || c == 127) {
            int remaining = max_len - dest_pos - 1;
            int written;
            
            // Skip null bytes
            if (c == 0) {
                continue;
            }
            
            // Use mnemonic names for common control chars
            if (c == '\r') {
                written = snprintf(dest + dest_pos, remaining, "\\r");
            } else if (c == '\n') {
                written = snprintf(dest + dest_pos, remaining, "\\n");
            } else if (c == '\t') {
                written = snprintf(dest + dest_pos, remaining, "\\t");
            } else {
                // Use hex notation for other control chars
                written = snprintf(dest + dest_pos, remaining, "\\x%02x", c);
            }
            
            if (written > 0) {
                dest_pos += written;
            }
        }
        // Non-ASCII characters
        else if (c > 127) {
            int remaining = max_len - dest_pos - 1;
            int written = snprintf(dest + dest_pos, remaining, "\\x%02x", c);
            
            if (written > 0) {
                dest_pos += written;
            }
        }
        // Normal printable ASCII
        else {
            dest[dest_pos++] = c;
        }
        
        // Check for buffer overflow
        if (dest_pos >= max_len - 1) {
            break;
        }
    }
    
    // Null terminate
    dest[dest_pos] = '\0';
    return dest_pos;
}

/**
 * @brief Process a command received from a client and generate a response
 * 
 * @param client_socket The client socket to send the response to
 * @param cmd The command to process
 * @param client_addr The client address information
 */
static void process_command(int client_socket, const char *cmd, struct sockaddr_in *client_addr) {
    if (!cmd || strlen(cmd) == 0) {
        return; // Skip empty commands
    }
    
    // Simulate command processing delay
    vTaskDelay(pdMS_TO_TICKS(50 + (rand() % 150))); // Random delay between 50-200ms
    
    // Sanitize the command for logging
    char sanitized_cmd[MAX_CMD_LENGTH];
    sanitize_command(sanitized_cmd, cmd, MAX_CMD_LENGTH);
    
    // Log the command (and send webhook alert)
    log_client_command(sanitized_cmd, client_addr);
    
    // Buffer for response
    char response[2048];
    memset(response, 0, sizeof(response));
    
    // Command comparison helpers
    const char *cmd_trimmed = cmd;
    while(*cmd_trimmed && isspace((unsigned char)*cmd_trimmed)) {
        cmd_trimmed++; // Skip leading whitespace
    }
    
    // Log the command with client information
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(client_addr->sin_addr), ip_str, INET_ADDRSTRLEN) != NULL) {
        ESP_LOGI(TAG, "Processing command: '%s' from IP: %s", sanitized_cmd, ip_str);
    }
    
    // Process based on command
    if (strcmp(cmd_trimmed, "exit") == 0 || strcmp(cmd_trimmed, "quit") == 0 || 
        strcmp(cmd_trimmed, "logout") == 0) {
        // Handle exit commands
        snprintf(response, sizeof(response), 
                 "Connection closed by foreign host.\r\n");
    } 
    else if (strncmp(cmd_trimmed, "cd ", 3) == 0) {
        // Simulate changing directory
        response[0] = '\0'; // No output on success
    }
    else if (strcmp(cmd_trimmed, "pwd") == 0) {
        // Print working directory
        snprintf(response, sizeof(response), "/home/user\r\n");
    }
    else if (strcmp(cmd_trimmed, "whoami") == 0) {
        // Print user
        snprintf(response, sizeof(response), "user\r\n");
    }
    else if (strcmp(cmd_trimmed, "id") == 0) {
        // Print user id info
        snprintf(response, sizeof(response), 
                 "uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\r\n");
    }
    else if (strcmp(cmd_trimmed, "hostname") == 0) {
        // Print hostname
        snprintf(response, sizeof(response), "ubuntu-server\r\n");
    }
    else if (strcmp(cmd_trimmed, "uptime") == 0) {
        // Generate random uptime
        int days = 10 + (rand() % 90);  // 10-99 days
        int hours = rand() % 24;        // 0-23 hours
        int minutes = rand() % 60;      // 0-59 minutes
        int users = 1 + (rand() % 3);   // 1-3 users
        float load1 = (float)(rand() % 100) / 100.0f;  // 0.00-0.99 load
        float load5 = (float)(rand() % 80) / 100.0f;   // 0.00-0.79 load
        float load15 = (float)(rand() % 50) / 100.0f;  // 0.00-0.49 load
        
        snprintf(response, sizeof(response), 
                 " %02d:%02d:%02d up %d days, %d:%02d, %d user%s,  load average: %.2f, %.2f, %.2f\r\n",
                 (8 + hours) % 24, minutes, rand() % 60, 
                 days, hours, minutes, 
                 users, (users == 1 ? "" : "s"),
                 load1, load5, load15);
    }
    else if (strcmp(cmd_trimmed, "ps aux") == 0 || strcmp(cmd_trimmed, "ps -ef") == 0) {
        // Process list
        snprintf(response, sizeof(response), 
                "USER       PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
                "root         1  0.0  0.1 168432 11248 ?        Ss   Sep18   0:14 /sbin/init splash\r\n"
                "root         2  0.0  0.0      0     0 ?        S    Sep18   0:00 [kthreadd]\r\n"
                "root         3  0.0  0.0      0     0 ?        I<   Sep18   0:00 [rcu_gp]\r\n"
                "root         4  0.0  0.0      0     0 ?        I<   Sep18   0:00 [rcu_par_gp]\r\n"
                "root         8  0.0  0.0      0     0 ?        I<   Sep18   0:00 [mm_percpu_wq]\r\n"
                "root        10  0.0  0.0      0     0 ?        S    Sep18   0:00 [ksoftirqd/0]\r\n"
                "root        11  0.0  0.0      0     0 ?        I    Sep18   0:19 [rcu_sched]\r\n"
                "root        12  0.0  0.0      0     0 ?        S    Sep18   0:00 [migration/0]\r\n"
                "root      1036  0.0  0.5  72108 44436 ?        Ss   Sep18   0:02 /usr/bin/containerd\r\n"
                "root      1095  0.0  0.1 235364 15384 ?        Ssl  Sep18   0:00 /usr/lib/accountsservice/accounts-daemon\r\n"
                "root      1102  0.0  0.0  81836  3612 ?        Ssl  Sep18   0:00 /usr/sbin/irqbalance --foreground\r\n"
                "root      1106  0.0  0.5 1519748 41576 ?       Ssl  Sep18   0:12 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock\r\n"
                "root      1110  0.0  0.1 236804  8040 ?        Ssl  Sep18   0:00 /usr/lib/policykit-1/polkitd --no-debug\r\n"
                "root      1134  0.0  0.2 264056 16836 ?        Ssl  Sep18   0:00 /usr/sbin/NetworkManager --no-daemon\r\n"
                "root      1143  0.0  0.4 1258560 35964 ?       Ssl  Sep18   0:04 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers\r\n"
                "root      1154  0.0  0.1 396384 13668 ?        Ssl  Sep18   0:01 /usr/lib/udisks2/udisksd\r\n"
                "user      2109  0.0  0.1  12108  5552 pts/0    Ss   14:23   0:00 -bash\r\n"
                "user      2315  0.0  0.0  13216  3168 pts/0    R+   14:24   0:00 ps aux\r\n");
    }
    else if (strcmp(cmd_trimmed, "w") == 0) {
        // Who is logged in
        int minutes = rand() % 60;      // 0-59 minutes
        int seconds = rand() % 60;      // 0-59 seconds
        int ipLastOctet = (rand() % 254) + 1;
        snprintf(response, sizeof(response), 
                " 14:%02d:%02d up 10 days, 22:47,  1 user,  load average: 0.08, 0.02, 0.01\r\n"
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n"
                "user     pts/0    192.168.1.%d     14:23    0.00s  0.06s  0.00s w\r\n",
                minutes, seconds, ipLastOctet);
    }
    else if (strcmp(cmd_trimmed, "last") == 0) {
        // Last logged in users
        int day = (rand() % 28) + 1;
        int hour = (rand() % 24);
        int minute = (rand() % 60);
        snprintf(response, sizeof(response), 
                "user     pts/0        192.168.1.%d    Sun Oct %d %02d:%02d   still logged in\r\n"
                "reboot   system boot  5.15.0-52-generi Sun Oct %d %02d:%02d   still running\r\n"
                "user     pts/0        192.168.1.%d    Sun Oct %d %02d:%02d - %02d:%02d  (00:%02d)\r\n"
                "reboot   system boot  5.15.0-52-generi Sun Oct %d %02d:%02d - %02d:%02d  (00:%02d)\r\n"
                "\r\n"
                "wtmp begins Sun Oct %d %02d:%02d:40 2023\r\n",
                (rand() % 254) + 1, day, hour, minute,
                day, hour, minute - 5,
                (rand() % 254) + 1, day-1, hour-1, minute-10, hour, minute-5, minute+5,
                day-1, hour-2, minute-20, hour-1, minute-15, minute+5,
                day-10, 8, 30);
    }
    else if (strcmp(cmd_trimmed, "free -h") == 0 || strcmp(cmd_trimmed, "free") == 0) {
        // Memory usage
        snprintf(response, sizeof(response), 
                "               total        used        free      shared  buff/cache   available\r\n"
                "Mem:           7.7Gi       2.3Gi       2.7Gi       320Mi       2.7Gi       4.8Gi\r\n"
                "Swap:          2.0Gi          0B       2.0Gi\r\n");
    }
    else if (strcmp(cmd_trimmed, "df -h") == 0) {
        // Disk usage
        snprintf(response, sizeof(response), 
                "Filesystem      Size  Used Avail Use%% Mounted on\r\n"
                "udev            3.9G     0  3.9G   0%% /dev\r\n"
                "tmpfs           799M  1.7M  797M   1%% /run\r\n"
                "/dev/sda1       234G   48G  175G  22%% /\r\n"
                "tmpfs           3.9G   65M  3.9G   2%% /dev/shm\r\n"
                "tmpfs           5.0M  4.0K  5.0M   1%% /run/lock\r\n"
                "/dev/sda2       511M  7.8M  504M   2%% /boot/efi\r\n");
    }
    else if (strcmp(cmd_trimmed, "ifconfig") == 0 || strcmp(cmd_trimmed, "ip addr") == 0) {
        // Network interfaces
        snprintf(response, sizeof(response), 
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                "        inet 192.168.1.%d  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
                "        inet6 fe80::216:3eff:fe12:%d  prefixlen 64  scopeid 0x20<link>\r\n"
                "        ether 00:16:3e:12:%02x:%02x  txqueuelen 1000  (Ethernet)\r\n"
                "        RX packets 843884  bytes 284333939 (284.3 MB)\r\n"
                "        RX errors 0  dropped 0  overruns 0  frame 0\r\n"
                "        TX packets 480298  bytes 122474753 (122.4 MB)\r\n"
                "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n"
                "\r\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
                "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\r\n"
                "        loop  txqueuelen 1000  (Local Loopback)\r\n"
                "        RX packets 113605  bytes 22505254 (22.5 MB)\r\n"
                "        RX errors 0  dropped 0  overruns 0  frame 0\r\n"
                "        TX packets 113605  bytes 22505254 (22.5 MB)\r\n"
                "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n",
                10 + (rand() % 90),
                1000 + (rand() % 9000),
                (rand() % 255),
                (rand() % 255));
    }
    else if (strcmp(cmd_trimmed, "netstat -an") == 0 || strcmp(cmd_trimmed, "netstat") == 0) {
        // Network connections
        int port1 = 1024 + (rand() % 60000);
        int port2 = 1024 + (rand() % 60000);
        snprintf(response, sizeof(response), 
                "Active Internet connections (servers and established)\r\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 192.168.1.10:23         %s:%d        ESTABLISHED\r\n"
                "tcp        0      0 192.168.1.10:22         192.168.1.%d:%d       ESTABLISHED\r\n"
                "tcp6       0      0 :::22                   :::*                    LISTEN\r\n"
                "tcp6       0      0 :::80                   :::*                    LISTEN\r\n"
                "udp        0      0 0.0.0.0:68              0.0.0.0:*\r\n"
                "udp        0      0 0.0.0.0:5353            0.0.0.0:*\r\n"
                "udp6       0      0 :::5353                 :::*\r\n",
                ip_str, port1,
                50 + (rand() % 99), port2);
    }
    else if (strcmp(cmd_trimmed, "history") == 0) {
        // Command history
        snprintf(response, sizeof(response), 
                "    1  ls -la\r\n"
                "    2  cd /var/log\r\n"
                "    3  cat syslog\r\n"
                "    4  ps aux | grep apache\r\n"
                "    5  tail -f /var/log/auth.log\r\n"
                "    6  cd /etc\r\n"
                "    7  cat shadow\r\n"
                "    8  sudo cat shadow\r\n"
                "    9  cd\r\n"
                "   10  mkdir backup\r\n"
                "   11  mysql -u root -p\r\n"
                "   12  vim /etc/ssh/sshd_config\r\n"
                "   13  systemctl restart ssh\r\n"
                "   14  ifconfig\r\n"
                "   15  wget http://install.sh\r\n"
                "   16  chmod +x install.sh\r\n"
                "   17  ./install.sh\r\n"
                "   18  history\r\n");
    }
    else if (strncmp(cmd_trimmed, "cat ", 4) == 0) {
        // Extract the file path
        const char *filepath = cmd_trimmed + 4;
        
        // Implement specific file emulation
        if (strcmp(filepath, "/etc/passwd") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_ETC_PASSWD);
        } 
        else if (strcmp(filepath, "/etc/secrets.txt") == 0 || 
                 strcmp(filepath, "secrets.txt") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_SECRETS_TXT);
        }
        else if (strcmp(filepath, "/etc/db.conf") == 0 || 
                 strcmp(filepath, "db.conf") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_DB_CONFIG);
        }
        else if (strcmp(filepath, "/etc/hosts") == 0) {
            snprintf(response, sizeof(response), 
                    "127.0.0.1 localhost\r\n"
                    "127.0.1.1 ubuntu-server\r\n"
                    "\r\n"
                    "# The following lines are desirable for IPv6 capable hosts\r\n"
                    "::1     ip6-localhost ip6-loopback\r\n"
                    "fe00::0 ip6-localnet\r\n"
                    "ff00::0 ip6-mcastprefix\r\n"
                    "ff02::1 ip6-allnodes\r\n"
                    "ff02::2 ip6-allrouters\r\n");
        }
        else if (strcmp(filepath, "/etc/shadow") == 0) {
            snprintf(response, sizeof(response), 
                    "cat: /etc/shadow: Permission denied\r\n");
        }
        else if (strcmp(filepath, "/etc/issue") == 0) {
            snprintf(response, sizeof(response), "Ubuntu 20.04.5 LTS \\n \\l\r\n");
        }
        else if (strcmp(filepath, "/proc/version") == 0) {
            snprintf(response, sizeof(response), "Linux version 5.15.0-52-generic (buildd@ubuntu) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0) #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022\r\n");
        }
        else if (strcmp(filepath, "/proc/cpuinfo") == 0) {
            snprintf(response, sizeof(response), 
                    "processor   : 0\r\n"
                    "vendor_id   : GenuineIntel\r\n"
                    "cpu family  : 6\r\n"
                    "model       : 158\r\n"
                    "model name  : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz\r\n"
                    "stepping    : 10\r\n"
                    "microcode   : 0xca\r\n"
                    "cpu MHz     : 1992.002\r\n"
                    "cache size  : 8192 KB\r\n"
                    "\r\n"
                    "processor   : 1\r\n"
                    "vendor_id   : GenuineIntel\r\n"
                    "cpu family  : 6\r\n"
                    "model       : 158\r\n"
                    "model name  : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz\r\n"
                    "stepping    : 10\r\n"
                    "microcode   : 0xca\r\n"
                    "cpu MHz     : 1992.002\r\n"
                    "cache size  : 8192 KB\r\n");
        }
        else if (strcmp(filepath, "/etc/ssh/sshd_config") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_SSH_CONFIG);
        }
        else if (strcmp(filepath, "/etc/nginx/nginx.conf") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_NGINX_CONFIG);
        }
        else if (strcmp(filepath, "/home/user/.ssh/id_rsa") == 0 || 
                 strcmp(filepath, "~/.ssh/id_rsa") == 0 || 
                 strcmp(filepath, ".ssh/id_rsa") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_SSH_KEY);
        }
        else if (strcmp(filepath, "/home/user/.aws/credentials") == 0 || 
                 strcmp(filepath, "~/.aws/credentials") == 0 || 
                 strcmp(filepath, ".aws/credentials") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_AWS_CREDENTIALS);
        }
        else if (strcmp(filepath, ".env") == 0 || 
                 strcmp(filepath, "/var/www/html/.env") == 0) {
            snprintf(response, sizeof(response), "%s", FAKE_ENV_FILE);
        }
        else {
            // File not found for other files
            snprintf(response, sizeof(response), 
                     "cat: %s: No such file or directory\r\n", filepath);
        }
    }
    else if (strcmp(cmd_trimmed, "ls") == 0 || strcmp(cmd_trimmed, "ls -la") == 0 || 
             strcmp(cmd_trimmed, "ls -l") == 0 || strcmp(cmd_trimmed, "ls -a") == 0) {
        // Simulate ls command
        if (strcmp(cmd_trimmed, "ls") == 0) {
            // Simple listing
            snprintf(response, sizeof(response), 
                     "Desktop    Documents    Downloads    Music    Pictures    Public    Videos\r\n");
        } else {
            // Detailed listing
            snprintf(response, sizeof(response), 
                     "total 40\r\n"
                     "drwxr-xr-x 6 user user 4096 Oct  7 14:23 .\r\n"
                     "drwxr-xr-x 3 root root 4096 Sep 18 09:12 ..\r\n"
                     "-rw------- 1 user user  165 Oct  7 14:23 .bash_history\r\n"
                     "-rw-r--r-- 1 user user  220 Sep 18 09:12 .bash_logout\r\n"
                     "-rw-r--r-- 1 user user 3771 Sep 18 09:12 .bashrc\r\n"
                     "drwxr-xr-x 2 user user 4096 Sep 18 09:12 Desktop\r\n"
                     "drwxr-xr-x 2 user user 4096 Sep 18 09:12 Documents\r\n"
                     "drwxr-xr-x 2 user user 4096 Sep 18 09:12 Downloads\r\n"
                     "-rw-r--r-- 1 user user    0 Sep 18 09:12 .motd_shown\r\n"
                     "drwxr-xr-x 2 user user 4096 Sep 18 09:12 Music\r\n"
                     "drwxr-xr-x 2 user user 4096 Sep 18 09:12 Pictures\r\n"
                     "-rw-r--r-- 1 user user  807 Sep 18 09:12 .profile\r\n"
                     "drwxr-xr-x 2 user user 4096 Sep 18 09:12 Public\r\n"
                     "-rw-r--r-- 1 user user    0 Sep 18 09:13 .sudo_as_admin_successful\r\n"
                     "drwxr-xr-x 2 user user 4096 Sep 18 09:12 Videos\r\n");
        }
    }
    else if (strncmp(cmd_trimmed, "uname", 5) == 0) {
        // Simulate uname command
        if (strcmp(cmd_trimmed, "uname -a") == 0) {
            snprintf(response, sizeof(response), 
                    "Linux ubuntu-server 5.15.0-52-generic #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux\r\n");
        } else {
            snprintf(response, sizeof(response), "Linux\r\n");
        }
    }
    else if (strncmp(cmd_trimmed, "ping", 4) == 0) {
        // Ping emulation
        const char *target = "127.0.0.1";  // Default target
        
        if (strlen(cmd_trimmed) > 5) {
            target = cmd_trimmed + 5;  // Skip "ping "
        }
        
        snprintf(response, sizeof(response), 
                "PING %s (127.0.0.1) 56(84) bytes of data.\r\n"
                "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.022 ms\r\n"
                "64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.023 ms\r\n"
                "64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.027 ms\r\n"
                "64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.030 ms\r\n"
                "^C\r\n"
                "--- %s ping statistics ---\r\n"
                "4 packets transmitted, 4 received, 0%% packet loss, time 3056ms\r\n"
                "rtt min/avg/max/mdev = 0.022/0.025/0.030/0.003 ms\r\n",
                target, target);
    }
    else if (strncmp(cmd_trimmed, "sudo", 4) == 0) {
        // Sudo simulation
        snprintf(response, sizeof(response), 
                "[sudo] password for user: ");
        safe_send(client_socket, response, strlen(response));
        
        // Wait a moment as if user is typing password
        vTaskDelay(pdMS_TO_TICKS(1500));
        
        snprintf(response, sizeof(response), 
                "\r\nuser is not in the sudoers file.  This incident will be reported.\r\n");
    }
    else if (strcmp(cmd_trimmed, "lscpu") == 0) {
        // CPU information
        snprintf(response, sizeof(response), 
                "Architecture:        x86_64\r\n"
                "CPU op-mode(s):      32-bit, 64-bit\r\n"
                "Byte Order:          Little Endian\r\n"
                "CPU(s):              4\r\n"
                "On-line CPU(s) list: 0-3\r\n"
                "Thread(s) per core:  2\r\n"
                "Core(s) per socket:  2\r\n"
                "Socket(s):           1\r\n"
                "NUMA node(s):        1\r\n"
                "Vendor ID:           GenuineIntel\r\n"
                "CPU family:          6\r\n"
                "Model:               158\r\n"
                "Model name:          Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz\r\n"
                "Stepping:            10\r\n"
                "CPU MHz:             1992.002\r\n"
                "CPU max MHz:         4600.0000\r\n"
                "CPU min MHz:         400.0000\r\n"
                "BogoMIPS:            3984.00\r\n"
                "Virtualization:      VT-x\r\n"
                "L1d cache:           32K\r\n"
                "L1i cache:           32K\r\n"
                "L2 cache:            256K\r\n"
                "L3 cache:            8192K\r\n"
                "NUMA node0 CPU(s):   0-3\r\n");
    }
    else if (strncmp(cmd_trimmed, "mkdir ", 6) == 0) {
        // Simulate directory creation - no need to use dir_name variable
        response[0] = '\0'; // No output on success
    }
    else if (strncmp(cmd_trimmed, "rm ", 3) == 0) {
        // Simulate file removal
        const char *options = cmd_trimmed + 3;
        if (strstr(options, "-rf") != NULL) {
            // Warning for recursive removal
            response[0] = '\0'; // No output on success
        } else {
            response[0] = '\0'; // No output on success
        }
    }
    else if (strncmp(cmd_trimmed, "rmdir ", 6) == 0) {
        // Simulate directory removal - no need to use dir_name variable
        response[0] = '\0'; // No output on success
    }
    else if (strncmp(cmd_trimmed, "touch ", 6) == 0) {
        // Simulate file creation/update timestamp - no need to use file_name variable
        response[0] = '\0'; // No output on success
    }
    else if (strncmp(cmd_trimmed, "chmod ", 6) == 0) {
        // Simulate changing file permissions - no need to use args variable
        response[0] = '\0'; // No output on success
    }
    else if (strncmp(cmd_trimmed, "chown ", 6) == 0) {
        // Simulate changing file ownership - no need to use args variable
        response[0] = '\0'; // No output on success
    }
    else if (strncmp(cmd_trimmed, "service ", 8) == 0) {
        // service <service_name> <action>
        char service_name[64] = {0};
        char action[16] = {0};
        
        // Extract service name and action
        const char *args = cmd_trimmed + 8;
        sscanf(args, "%63s %15s", service_name, action);
        
        if (strlen(service_name) == 0) {
            snprintf(response, sizeof(response), 
                    "Usage: service <service_name> {start|stop|status|restart}\r\n");
        } else if (strcmp(action, "start") == 0) {
            snprintf(response, sizeof(response), 
                    "Starting %s service...\r\n"
                    " * Starting %s service                                 [ OK ]\r\n",
                    service_name, service_name);
        } else if (strcmp(action, "stop") == 0) {
            snprintf(response, sizeof(response), 
                    "Stopping %s service...\r\n"
                    " * Stopping %s service                                 [ OK ]\r\n",
                    service_name, service_name);
        } else if (strcmp(action, "restart") == 0) {
            snprintf(response, sizeof(response), 
                    "Restarting %s service...\r\n"
                    " * Stopping %s service                                 [ OK ]\r\n"
                    " * Starting %s service                                 [ OK ]\r\n",
                    service_name, service_name, service_name);
        } else if (strcmp(action, "status") == 0) {
            // Randomize status
            int random_status = rand() % 3; // 0=running, 1=stopped, 2=failed
            const char *status_text[] = {"active (running)", "inactive (dead)", "failed"};
            
            snprintf(response, sizeof(response), 
                    "● %s.service - %s service\r\n"
                    "     Loaded: loaded (/lib/systemd/system/%s.service; enabled; vendor preset: enabled)\r\n"
                    "     Active: %s since Tue 2023-10-24 %02d:%02d:%02d UTC; %d min ago\r\n"
                    "    Process: %d ExecStart=/usr/sbin/%s start (code=exited, status=%d)\r\n"
                    "   Main PID: %d (code=exited, status=%d)\r\n"
                    "      Tasks: %d\r\n"
                    "     Memory: %d.%dM\r\n"
                    "        CPU: %dms\r\n",
                    service_name, service_name, 
                    service_name,
                    status_text[random_status], 
                    8 + (rand() % 8), rand() % 60, rand() % 60, 
                    rand() % 120,
                    1000 + (rand() % 5000), service_name, random_status ? 1 : 0,
                    1000 + (rand() % 5000), random_status ? 1 : 0,
                    random_status ? 0 : (1 + (rand() % 24)),
                    10 + (rand() % 100), rand() % 10,
                    100 + (rand() % 900));
        } else {
            snprintf(response, sizeof(response), 
                    "Usage: service <service_name> {start|stop|status|restart}\r\n");
        }
    }
    else if (strncmp(cmd_trimmed, "systemctl ", 10) == 0) {
        // systemctl <action> <service_name>
        char action[16] = {0};
        char service_name[64] = {0};
        
        // Extract action and service name
        const char *args = cmd_trimmed + 10;
        sscanf(args, "%15s %63s", action, service_name);
        
        if (strlen(service_name) == 0) {
            snprintf(response, sizeof(response), 
                    "Usage: systemctl {start|stop|status|restart} <service_name>\r\n");
        } else if (strcmp(action, "start") == 0) {
            snprintf(response, sizeof(response), 
                    "Starting %s.service...\r\n",
                    service_name);
        } else if (strcmp(action, "stop") == 0) {
            snprintf(response, sizeof(response), 
                    "Stopping %s.service...\r\n",
                    service_name);
        } else if (strcmp(action, "restart") == 0) {
            snprintf(response, sizeof(response), 
                    "Restarting %s.service...\r\n",
                    service_name);
        } else if (strcmp(action, "status") == 0) {
            // Randomize status
            int random_status = rand() % 3; // 0=running, 1=stopped, 2=failed
            const char *status_text[] = {"active (running)", "inactive (dead)", "failed"};
            
            snprintf(response, sizeof(response), 
                    "● %s.service - %s service\r\n"
                    "     Loaded: loaded (/lib/systemd/system/%s.service; enabled; vendor preset: enabled)\r\n"
                    "     Active: %s since Tue 2023-10-24 %02d:%02d:%02d UTC; %d min ago\r\n"
                    "   Main PID: %d (code=exited, status=%d)\r\n"
                    "      Tasks: %d\r\n"
                    "     Memory: %d.%dM\r\n"
                    "        CPU: %dms\r\n",
                    service_name, service_name, 
                    service_name,
                    status_text[random_status], 
                    8 + (rand() % 8), rand() % 60, rand() % 60, 
                    rand() % 120,
                    1000 + (rand() % 5000), random_status ? 1 : 0,
                    random_status ? 0 : (1 + (rand() % 24)),
                    10 + (rand() % 100), rand() % 10,
                    100 + (rand() % 900));
        } else {
            snprintf(response, sizeof(response), 
                    "Usage: systemctl {start|stop|status|restart} <service_name>\r\n");
        }
    }
    else if (strncmp(cmd_trimmed, "apt-get ", 8) == 0) {
        const char *apt_cmd = cmd_trimmed + 8;
        
        if (strncmp(apt_cmd, "update", 6) == 0) {
            snprintf(response, sizeof(response), 
                    "Hit:1 http://security.ubuntu.com/ubuntu focal-security InRelease\r\n"
                    "Hit:2 http://archive.ubuntu.com/ubuntu focal InRelease\r\n"
                    "Hit:3 http://archive.ubuntu.com/ubuntu focal-updates InRelease\r\n"
                    "Hit:4 http://archive.ubuntu.com/ubuntu focal-backports InRelease\r\n"
                    "Reading package lists... Done\r\n"
                    "Building dependency tree\r\n"
                    "Reading state information... Done\r\n"
                    "All packages are up to date.\r\n");
        } 
        else if (strncmp(apt_cmd, "install", 7) == 0) {
            // Extract package name
            const char *package = apt_cmd + 8;
            while (*package && isspace((unsigned char)*package)) package++;
            
            if (strlen(package) == 0) {
                snprintf(response, sizeof(response), 
                        "E: No package name specified\r\n");
            } else {
                snprintf(response, sizeof(response), 
                        "Reading package lists... Done\r\n"
                        "Building dependency tree\r\n"
                        "Reading state information... Done\r\n"
                        "The following NEW packages will be installed:\r\n"
                        "  %s\r\n"
                        "0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\r\n"
                        "Need to get %d kB of archives.\r\n"
                        "After this operation, %d kB of additional disk space will be used.\r\n"
                        "Get:1 http://archive.ubuntu.com/ubuntu focal/main amd64 %s amd64 1.0-%d [%d kB]\r\n"
                        "Fetched %d kB in %d.%d s (%d kB/s)\r\n"
                        "Selecting previously unselected package %s.\r\n"
                        "(Reading database ... %d files and directories currently installed.)\r\n"
                        "Preparing to unpack .../archives/%s_1.0-%d_amd64.deb ...\r\n"
                        "Unpacking %s (1.0-%d) ...\r\n"
                        "Setting up %s (1.0-%d) ...\r\n"
                        "Processing triggers for libc-bin (2.31-0ubuntu9.9) ...\r\n",
                        package,
                        100 + (rand() % 900),
                        200 + (rand() % 800),
                        package, rand() % 20, 100 + (rand() % 900),
                        100 + (rand() % 900),
                        1 + (rand() % 10), rand() % 10,
                        50 + (rand() % 500),
                        package,
                        100000 + (rand() % 50000),
                        package, rand() % 20,
                        package, rand() % 20,
                        package, rand() % 20);
            }
        }
        else if (strncmp(apt_cmd, "upgrade", 7) == 0) {
            snprintf(response, sizeof(response), 
                    "Reading package lists... Done\r\n"
                    "Building dependency tree\r\n"
                    "Reading state information... Done\r\n"
                    "Calculating upgrade... Done\r\n"
                    "The following packages will be upgraded:\r\n"
                    "  libc6 openssh-client openssh-server openssl python3-crypto\r\n"
                    "5 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\r\n"
                    "Need to get 6,922 kB of archives.\r\n"
                    "After this operation, 24.6 kB of additional disk space will be used.\r\n"
                    "Do you want to continue? [Y/n] Y\r\n"
                    "Get:1 http://archive.ubuntu.com/ubuntu focal-security/main amd64 libc6 amd64 2.31-0ubuntu9.9 [2,520 kB]\r\n"
                    "Get:2 http://archive.ubuntu.com/ubuntu focal-security/main amd64 openssh-client amd64 1:8.2p1-4ubuntu0.5 [671 kB]\r\n"
                    "Get:3 http://archive.ubuntu.com/ubuntu focal-security/main amd64 openssh-server amd64 1:8.2p1-4ubuntu0.5 [382 kB]\r\n"
                    "Get:4 http://archive.ubuntu.com/ubuntu focal-security/main amd64 openssl amd64 1.1.1f-1ubuntu2.16 [620 kB]\r\n"
                    "Get:5 http://archive.ubuntu.com/ubuntu focal-security/main amd64 python3-crypto amd64 2.6.1-13ubuntu2.1 [240 kB]\r\n"
                    "Fetched 4,433 kB in 3s (1,429 kB/s)\r\n"
                    "Preconfiguring packages ...\r\n"
                    "(Reading database ... 131215 files and directories currently installed.)\r\n"
                    "Preparing to unpack .../libc6_2.31-0ubuntu9.9_amd64.deb ...\r\n"
                    "Unpacking libc6:amd64 (2.31-0ubuntu9.9) over (2.31-0ubuntu9.7) ...\r\n"
                    "Setting up libc6:amd64 (2.31-0ubuntu9.9) ...\r\n"
                    "Processing triggers for libc-bin (2.31-0ubuntu9.9) ...\r\n"
                    "/sbin/ldconfig.real: /usr/local/lib/python3.8/dist-packages/ideep4py/lib/libmkldnn.so.0 is not a symbolic link\r\n"
                    "\r\n"
                    "Processing triggers for man-db (2.9.1-1) ...\r\n");
        }
        else {
            snprintf(response, sizeof(response), 
                    "E: Invalid operation %s\r\n", apt_cmd);
        }
    }
    else if (strcmp(cmd_trimmed, "apt list") == 0 || strcmp(cmd_trimmed, "apt list --installed") == 0) {
        snprintf(response, sizeof(response), 
                "Listing... Done\r\n"
                "adduser/focal,now 3.118ubuntu2 all [installed]\r\n"
                "apt/focal-updates,now 2.0.9 amd64 [installed]\r\n"
                "base-files/focal-updates,now 11ubuntu5.5 amd64 [installed]\r\n"
                "bash/focal-updates,now 5.0-6ubuntu1.2 amd64 [installed]\r\n"
                "coreutils/focal,now 8.30-3ubuntu2 amd64 [installed]\r\n"
                "dash/focal,now 0.5.10.2-6 amd64 [installed]\r\n"
                "debconf/focal,now 1.5.73 all [installed]\r\n"
                "dpkg/focal-updates,now 1.19.7ubuntu3.2 amd64 [installed]\r\n"
                "e2fsprogs/focal-updates,now 1.45.5-2ubuntu1.1 amd64 [installed]\r\n"
                "fdisk/focal,now 2.34-0.1ubuntu9.3 amd64 [installed]\r\n"
                "gcc/focal,now 4:9.3.0-1ubuntu2 amd64 [installed]\r\n"
                "git/focal-updates,now 1:2.25.1-1ubuntu3.6 amd64 [installed]\r\n"
                "initramfs-tools/focal-updates,now 0.136ubuntu6.7 all [installed]\r\n"
                "less/focal,now 551-1ubuntu0.1 amd64 [installed]\r\n"
                "libpython3.8/focal-updates,now 3.8.10-0ubuntu1~20.04.6 amd64 [installed]\r\n"
                "locales/focal,now 2.31-0ubuntu9.9 all [installed]\r\n"
                "login/focal-updates,now 1:4.8.1-1ubuntu5.20.04.2 amd64 [installed]\r\n"
                "make/focal,now 4.2.1-1.2 amd64 [installed]\r\n"
                "man-db/focal,now 2.9.1-1 amd64 [installed]\r\n"
                "nano/focal-updates,now 4.8-1ubuntu1 amd64 [installed]\r\n"
                "openssh-server/focal-security,now 1:8.2p1-4ubuntu0.5 amd64 [installed]\r\n"
                "sudo/focal,now 1.8.31-1ubuntu1.2 amd64 [installed]\r\n"
                "vim/focal,now 2:8.1.2269-1ubuntu5.9 amd64 [installed]\r\n"
                "wget/focal-updates,now 1.20.3-1ubuntu2 amd64 [installed]\r\n");
    }
    else {
        // Default response for unknown commands
        snprintf(response, sizeof(response), 
                 "-bash: %s: command not found\r\n", cmd_trimmed);
    }

    // Send the response if it's not empty
    if (strlen(response) > 0) {
        safe_send(client_socket, response, strlen(response));
    }
}

/**
 * Filter out telnet negotiation sequences and return a clean buffer
 * 
 * @param buffer The input buffer with potential telnet sequences
 * @param len The length of the buffer
 * @return The number of bytes in the cleaned buffer
 */
static int filter_telnet_commands(unsigned char *buffer, int len) {
    if (!buffer || len <= 0) {
        return 0;
    }
    
    int read_pos = 0;
    int write_pos = 0;
    
    while (read_pos < len) {
        // Check for IAC (Interpret As Command) byte
        if (buffer[read_pos] == IAC) {
            if (read_pos + 1 < len) {
                // Skip the IAC and the command byte
                if (buffer[read_pos + 1] == WILL || 
                    buffer[read_pos + 1] == WONT || 
                    buffer[read_pos + 1] == DO || 
                    buffer[read_pos + 1] == DONT) {
                    // These commands have 3 bytes, skip them all
                    read_pos += 3;
                    continue;
                } else if (buffer[read_pos + 1] == SB) {
                    // Subnegotiation - find the end (SE) or just skip rest of buffer
                    int i;
                    for (i = read_pos + 2; i < len - 1; i++) {
                        if (buffer[i] == IAC && buffer[i + 1] == SE) {
                            read_pos = i + 2;
                            break;
                        }
                    }
                    if (i >= len - 1) {
                        // No end found, skip to end of buffer
                        read_pos = len;
                    }
                    continue;
                } else {
                    // Other 2-byte commands
                    read_pos += 2;
                    continue;
                }
            }
        }
        
        // Move the byte to its new position
        buffer[write_pos++] = buffer[read_pos++];
    }
    
    // Null terminate the result if there's room
    if (write_pos < len) {
        buffer[write_pos] = '\0';
    }
    
    return write_pos;
}

/**
 * Send telnet initialization sequence to client
 */
static void send_telnet_init(int client_socket) {
    // Sequence to tell client we will echo, but don't negotiate other options
    static const unsigned char telnet_init[] = {
        IAC, WILL, 1,    // WILL ECHO
        IAC, DONT, 34,   // DONT LINEMODE
        IAC, WILL, 3,    // WILL SUPPRESS_GO_AHEAD
    };
    
    safe_send(client_socket, (const char *)telnet_init, sizeof(telnet_init));
}

static void handle_client(int client_socket, struct sockaddr_in *client_addr)
{
    if (client_socket < 0 || client_addr == NULL) {
        ESP_LOGE(TAG, "Invalid client connection");
        return;
    }
    
    // Seed the random number generator
    srand(time(NULL));
    
    // Take the client mutex
    if (client_mutex == NULL) {
        client_mutex = xSemaphoreCreateMutex();
        if (client_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create client mutex");
            close(client_socket);
            return;
        }
    }
    
    if (xSemaphoreTake(client_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to take client mutex");
        close(client_socket);
        return;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = RECV_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        ESP_LOGW(TAG, "Failed to set socket timeout");
        xSemaphoreGive(client_mutex);
        close(client_socket);
        return;
    }
    
    // Wait 800-1500ms before responding, like a real server would
    vTaskDelay(pdMS_TO_TICKS(800 + (rand() % 700)));
    
    // Send telnet protocol initialization
    send_telnet_init(client_socket);
    
    // Send welcome message with proper CRLF line endings
    static const char welcome[] = 
        "\r\n\r\nWelcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.15.0-52-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n"
        "\r\n"
        "  System information as of Sun Oct 15 14:23:18 UTC 2023\r\n"
        "\r\n"
        "  System load:  0.08               Processes:             128\r\n"
        "  Usage of /:   21.3% of 234.61GB  Users logged in:       1\r\n"
        "  Memory usage: 30%                IPv4 address for eth0: 192.168.1.10\r\n"
        "  Swap usage:   0%\r\n"
        "\r\n"
        " * Super-optimized for small spaces - read how we shrank the memory\r\n"
        "   footprint of MicroK8s to make it the smallest full K8s around.\r\n"
        "   https://ubuntu.com/blog/microk8s-memory-optimisation\r\n"
        "\r\n"
        "0 updates can be applied immediately.\r\n"
        "\r\n"
        "Last login: Sun Oct 15 14:10:22 2023 from 192.168.1.100\r\n"
        "user@ubuntu-server:~$ ";
    
    safe_send(client_socket, welcome, strlen(welcome));
    
    static const char prompt[] = "user@ubuntu-server:~$ ";
    static char buffer[BUFFER_SIZE];
    
    while (server_running) {
        // Clear buffer before receiving
        memset(buffer, 0, BUFFER_SIZE);
        
        // Use traditional blocking recv with timeout set by socket option
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            if (bytes_received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Just a timeout, continue
                    continue;
                }
                ESP_LOGW(TAG, "Error receiving data: %d", errno);
            }
            break;  // Connection closed or error
        }
        
        // Ensure null termination
        buffer[bytes_received] = '\0';
        
        // Filter out telnet commands and get clean data
        int clean_len = filter_telnet_commands((unsigned char *)buffer, bytes_received);
        if (clean_len > 0) {
            // Make sure it's properly terminated
            buffer[clean_len] = '\0';
            
            // Trim trailing CR/LF
            while (clean_len > 0 && (buffer[clean_len-1] == '\r' || buffer[clean_len-1] == '\n')) {
                buffer[--clean_len] = '\0';
            }
            
            // Process command if there's actual content
            if (clean_len > 0) {
                process_command(client_socket, buffer, client_addr);
            }
        }
        
        // Send prompt
        safe_send(client_socket, prompt, strlen(prompt));
    }
    
    ESP_LOGI(TAG, "Client disconnected: %s", inet_ntoa(client_addr->sin_addr));
    
    // Clean up
    close(client_socket);
    xSemaphoreGive(client_mutex);
}

void telnet_server_task(void *pvParameters)
{
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    ESP_LOGI(TAG, "Telnet server task started");
    
    while (server_running) {
        // Wait for connection
        ESP_LOGI(TAG, "Waiting for client connection...");
        
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
        
        if (client_socket < 0) {
            if (server_running) {
                ESP_LOGE(TAG, "Accept failed, errno: %d", errno);
                vTaskDelay(pdMS_TO_TICKS(1000));
            }
            continue;
        }
        
        // Log connection
        ESP_LOGI(TAG, "Client connected: %s", inet_ntoa(client_addr.sin_addr));
        
        // Handle client
        handle_client(client_socket, &client_addr);
    }
    
    vTaskDelete(NULL);
}

esp_err_t telnet_server_init(void)
{
    ESP_LOGI(TAG, "Initializing telnet server");
    
    // Create client mutex
    if (client_mutex == NULL) {
        client_mutex = xSemaphoreCreateMutex();
        if (client_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create client mutex");
            return ESP_FAIL;
        }
    }
    
    return ESP_OK;
}

esp_err_t telnet_server_start(void)
{
    if (server_running) {
        ESP_LOGW(TAG, "Telnet server already running");
        return ESP_OK;
    }
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        return ESP_FAIL;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        ESP_LOGE(TAG, "Unable to set socket options: errno %d", errno);
        close(server_socket);
        return ESP_FAIL;
    }
    
    // Bind to port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TELNET_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Socket bind failed: errno %d", errno);
        close(server_socket);
        return ESP_FAIL;
    }
    
    // Listen for connections
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        ESP_LOGE(TAG, "Socket listen failed: errno %d", errno);
        close(server_socket);
        return ESP_FAIL;
    }
    
    server_running = true;
    
    // Create server task
    BaseType_t task_created = xTaskCreate(
        telnet_server_task,
        "telnet_server",
        8192,
        NULL,
        5,
        &server_task_handle
    );
    
    if (task_created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create server task");
        close(server_socket);
        server_running = false;
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Telnet server started on port %d", TELNET_PORT);
    return ESP_OK;
}

esp_err_t telnet_server_stop(void)
{
    if (!server_running) {
        ESP_LOGW(TAG, "Telnet server not running");
        return ESP_OK;
    }
    
    server_running = false;
    
    // Close socket to interrupt accept()
    if (server_socket != -1) {
        close(server_socket);
        server_socket = -1;
    }
    
    // Wait for task to terminate
    if (server_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
        server_task_handle = NULL;
    }
    
    ESP_LOGI(TAG, "Telnet server stopped");
    return ESP_OK;
} 