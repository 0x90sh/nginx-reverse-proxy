# Nginx Dynamic Host Reverse Proxy

This project provides a simple Nginx dynamic host reverse proxy, designed for flexible and efficient routing of incoming HTTP requests to various backend services based on dynamic host configurations.

## Features

- **Dynamic Host Routing**: Routes incoming requests to backend services based on host configurations specified in a JSON file.
- **Ease of Configuration**: Simplifies the process of adding or modifying backend services without altering the core Nginx configuration.
- **Lightweight and Efficient**: Utilizes Nginx's event-driven architecture for high performance with minimal resource usage.

## Prerequisites

- **Docker**: Ensure Docker is installed on your system. Installation instructions can be found on the [official Docker website](https://docs.docker.com/get-docker/).
- **Docker Compose**: Verify that Docker Compose is installed. You can install it by following the [Docker Compose installation guide](https://docs.docker.com/compose/install/).
- **Cloudflare**: Make sure to use proxied cloudflare with flexible SSL to point to your proxy server. [Cloudflare](https://cloudflare.com)

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/0x90sh/nginx-reverse-proxy.git
   cd nginx-reverse-proxy
   ```

2. **Configure Hosts**:
   - Edit the `hosts.json` file to define your backend services. This file maps incoming hostnames to their respective upstream servers.
   - Example `hosts.json` structure:
     ```json
     {
       "example.com": "service_name",
       "anotherdomain.com": "service_name"
     }
     ```
   - In this configuration:
     - Requests to `example.com` will be proxied to `http://docker_service_ip:80`.
     - Requests to `anotherdomain.com` will be proxied to `http://docker_serivce_ip:80`.

3. **Start the Proxy**:
   - Use Docker Compose to build and start the Nginx reverse proxy service:
     ```bash
     docker-compose up -d
     ```
   - The `-d` flag runs the services in detached mode.

## Updating the Proxy

To update the proxy with the latest changes:

1. **Pull the Latest Changes**:
   ```bash
   git pull origin main
   ```

2. **Rebuild and Restart the Services**:
   ```bash
   docker-compose down
   docker-compose up -d --build
   ```
   - This will stop the running services, rebuild the Docker images with the latest changes, and start the services again in detached mode.

## Usage

Once the proxy is running:

- Ensure your DNS settings point the desired domain names to the server hosting this proxy.
- The proxy will route incoming HTTP requests to the appropriate backend services as defined in `hosts.json`.

## Contributing

Feel free to fork this repository and submit pull requests. Contributions are welcome!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Note: This project is intended for personal use. Ensure you understand the configuration and security implications before deploying it in a production environment.* 