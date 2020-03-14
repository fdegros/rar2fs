#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string_view>

#include <readline/readline.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

const char default_socket_path[] = "/tmp/password_socket";

struct Free {
        void operator()(void *p) { free(p); }
};

class ScopedFd
{
      public:
        explicit ScopedFd(int fd) : fd_(fd) {}
        ScopedFd(const ScopedFd &) = delete;
        ScopedFd &operator=(const ScopedFd &) = delete;

        ~ScopedFd()
        {
                if (close(fd_) < 0)
                        perror("Cannot close socket");
        }

      private:
        const int fd_;
};

int main(const int argc, char *const argv[])
{
        if (argc > 2) {
                std::cout << "Usage: password_server [socket_path]\n";
                return 2;
        }

        const char *const socket_path =
            argc == 2 ? argv[1] : default_socket_path;

        // Prepare socket.
        const int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sfd < 0) {
                const int err = errno;
                perror("Cannot create socket");
                return err;
        }

        const ScopedFd sfd_guard(sfd);

        if (unlink(socket_path) < 0 && errno != ENOENT) {
                const int err = errno;
                perror("Cannot remove old socket entry from file system");
                return err;
        }

        sockaddr_un addr;
        memset(&addr, 0, sizeof addr);
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path, sizeof addr.sun_path);

        if (bind(sfd, reinterpret_cast<const sockaddr *>(&addr), sizeof addr) <
            0) {
                const int err = errno;
                perror("Cannot bind socket to local path");
                return err;
        }

        if (listen(sfd, 5) < 0) {
                const int err = errno;
                perror("Cannot listen to socket");
                return err;
        }

        // Handle connections and requests one by one.
        while (true) {
                // Wait for connection.
                std::cout << "\nListening to " << std::quoted(socket_path)
                          << "...\n";
                const int cfd = accept(sfd, nullptr, nullptr);

                if (cfd < 0) {
                        perror("Cannot accept connection");
                        continue;
                }

                const ScopedFd cdf_guard(cfd);

                // Read request from socket.
                const size_t buf_size = 1024;
                char buf[buf_size];
                ssize_t nbytes = read(cfd, buf, buf_size);
                if (nbytes < 0) {
                        perror("Cannot read from socket");
                        continue;
                }

                const std::string_view filename(buf, nbytes);
                std::cout << "\nNeed password for " << std::quoted(filename)
                          << "\n";

                // Get password from user.
                std::unique_ptr<char[], Free> line(readline("Password? "));
                if (!line) {
                        std::cout << "\nBye bye\n";
                        return 0;
                }

                const std::string_view password(line.get());

                // Send response to socket.
                if (write(cfd, password.data(), password.size()) !=
                    password.size()) {
                        perror("Cannot write to socket");
                        continue;
                }

                std::cout << "Sent response containing "
                          << std::quoted(password) << "\n";
        }

        return 0;
}
