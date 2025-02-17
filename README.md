# HTTPlus-Server  
*A fast, multithreaded HTTP server with authentication & partial content support!*

##  Features
 **Multithreaded** - Handles multiple requests concurrently  
 **Basic Authentication** - Secure access with a username & password  
 **Custom Directory Serving** - Serve files from any folder  
 **Partial Content Support** - Resume downloads with HTTP range requests  
 **Lightweight & Easy to Use** - Run with a single command  

---

##  Installation
Install via **pip**:
```shell
pip install httplus-server
```

##  Usage
Run the server with default settings (binds to 0.0.0.0, port 8080, no authentication):

```shell
httplus-server
```
<br>

 Start with Custom Port
```shell
httplus-server 9090
```
<br>

 Enable Multithreading
```shell
httplus-server -p 8080 -t
```
<br>

 Serve a Specific Directory
```shell
httplus-server -p 8080 -d /path/to/directory
```
<br>

 Enable Basic Authentication
```shell
httplus-server -p 8080 -u myuser -P mypassword
```
<br>

 Full Example
```shell
httplus-server -b 0.0.0.0 -p 8000 -d mydir -u admin -P Secret123 -t
```
This starts a multithreaded HTTP server on port 8000, serving files from mydir/, requiring "admin" as the username and "Secret123" as the password.

##  Command Line Options
| Option        | Short | Description                                          | Default           |
|---------------|-------|------------------------------------------------------|-------------------|
| `--bind`      | `-b`  | Bind to a specific IP (e.g., `0.0.0.0`, `::`)       | `0.0.0.0`         |
| `--port`      | `-p`  | Port to listen on                                    | `8080`            |
| `--dir`       | `-d`  | Directory to serve files from                        | Current directory |
| `--user`      | `-u`  | Username for authentication                          | None (no auth)    |
| `--pass`      | `-P`  | Password for authentication                          | None (no auth)    |
| `--threaded`  | `-t`  | Enable multithreading                                | Off               |
