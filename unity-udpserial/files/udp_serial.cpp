#ifndef __UDP_SERIAL_CPP__
#define __UDP_SERIAL_CPP__

/**
 * @file udp_serial.cpp
 * @author Mohammed Naushad Ahmed (naushad.dln@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2023-01-15
 * 
 * @copyright Copyright (c) 2023
 * 
 */

 // openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
 
#include <iostream>
#include <array>
#include <memory>
#include <vector>


extern "C" {

	#include <string.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <termios.h>
	#include <unistd.h>
	#include <fcntl.h>
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <sys/types.h>
	#include <openssl/ssl.h>
	#include <openssl/err.h>
	#include <stdlib.h>
	#include <getopt.h>
}


class UdpSerial {
	public:
		UdpSerial() {
		}

		~UdpSerial() {
			this->close();
		}

		UdpSerial(std::string ip, std::uint16_t port, std::string path) {
			struct sockaddr_in addr;
			/* Set up the address we're going to bind to. */
			bzero(&addr, sizeof(addr));
  			addr.sin_family      = AF_INET;
  			addr.sin_port        = htons(port);
  			addr.sin_addr.s_addr = inet_addr(ip.c_str());
  			bzero( &addr.sin_zero, sizeof(addr.sin_zero ) );

			m_udpFd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(m_udpFd < 0) {
				std::cout << "Creation of UDP socket Failed" << std::endl;
				exit(-1);
			}

			/* set the reuse address flag so we don't get errors when restarting */
			auto flag = 1;
			if(::setsockopt(m_udpFd, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
				std::cout << "Error: Could not set reuse address option on DHCP socket!" << std::endl;
				exit(-1);
			}

			/* bind the socket */
			if(::bind(m_udpFd, (struct sockaddr *)&addr, sizeof(addr) ) < 0) 
			{
				std::cout << "Bind to ip:"<< ip << " port:" << port << " Failed" << std::endl;
				exit(-1);
			}

			m_serialFd = ::open(path.c_str(), (O_RDWR | O_NOCTTY | O_NONBLOCK));
			if(m_serialFd < 0) {
				std::cout << "Opening of Serial interface:" << path << " Failed" << std::endl;
				exit(-1);
			}

			/* taking the back up of current terminal settings */
			tcsetattr(m_serialFd, TCSANOW, &m_oldConfig);

			struct termios newtio;
			memset((void *)&newtio, 0, sizeof(struct termios));
	    	// set new port settings for canonical input processing
			auto baudrate = B115200;
			auto dataBits = CS8;
			auto stopBits = 0;
			auto parityOn = 0;
			auto parity = 0;

			newtio.c_cflag =  CRTSCTS | dataBits | stopBits | parityOn | parity   | CLOCAL | CREAD;
			newtio.c_iflag = 0;
			newtio.c_oflag = 0;
			newtio.c_lflag = 0;
			newtio.c_cc[VMIN] = 1;
			newtio.c_cc[VTIME] = 0;

			cfsetspeed(&newtio, baudrate);
			/* apply new terminal config now*/
			tcsetattr(m_serialFd, TCSANOW, &newtio);
		}

		void close() {
			/* re-store the original terminal config */
			tcsetattr(m_serialFd, TCSANOW, &m_oldConfig);
			::close(m_serialFd);
			::close(m_udpFd);
		}

		virtual int txToUdp(const std::string& req) {
			std::int32_t ret = -1;
			ret = ::sendto(m_udpFd, (void *)req.c_str(), req.length(), 0, (struct sockaddr *)&m_toAddr, sizeof(struct sockaddr));
			if(ret < 0) {
				std::cout << "sendto for IP:" << inet_ntoa(m_toAddr.sin_addr) << " port:" << m_toAddr.sin_port << " Failed" << std::endl;
			}
			return(ret);
		}

		int txToSerial(std::string& req) {
			ssize_t ret = -1;
			ret = ::write(m_serialFd, (void *)req.c_str(), req.length());

			if(ret < 0) {
				std::cout << " write to serial is failed" << std::endl;
				return(-1);
			}
			return(0);
		}

		virtual int rxFromUdp(std::string& rsp) {
			std::int32_t ret = -1;
			std::array<char, 1024> in;
			in.fill(0);
			socklen_t addr_len = sizeof(struct sockaddr_in);

			ret = ::recvfrom(m_udpFd, (void *)in.data(), in.size(), 0, (struct sockaddr *)&m_toAddr,  (socklen_t *)&addr_len);
			if(ret < 0) {
				std::cout << "Receive from UDP is Failed" << std::endl;
				return(ret);
			}
			
			std::string tmp((const char *)in.data(), ret);
			rsp = tmp;
			return(ret);
		}

		int rxFromSerial(std::string& rsp) {
			std::array<char, 2048> in;
			in.fill(0);
			ssize_t ret = -1;
			ret = ::read(m_serialFd, (void *)in.data(), in.size());
			if(ret < 0) {
				std::cout << "reading from serial is failed" << std::endl;
				return(-1);
			}

			std::string tmp((const char *)in.data(), ret);
			rsp = tmp;
			return(0);
		}

		int udp_channel() const {
			return(m_udpFd);
		}

		int start() {
			int conn_id   = -1;
			int num_bytes = -1;
   			fd_set fdList;

 			while (1) {
				/* A timeout for 5 secs*/ 
				struct timeval to;
 				to.tv_sec = 5;
 				to.tv_usec = 0;

		        FD_ZERO(&fdList);
 				FD_SET(m_udpFd, &fdList);
 				FD_SET(m_serialFd, &fdList);

				std::int32_t maxFd = (m_udpFd > m_serialFd) ? m_udpFd : m_serialFd;
				conn_id = ::select((maxFd + 1), (fd_set *)&fdList, (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)&to);
				if(conn_id > 0) {
					if(FD_ISSET(m_udpFd, &fdList ) ) {
						std::string request("");
						num_bytes = rxFromUdp(request);
						num_bytes = txToSerial(request);

      					} else if(FD_ISSET(m_serialFd, &fdList)) {

						std::string response("");
						num_bytes = rxFromSerial(response);
						num_bytes = txToUdp(response);
					} else {
						std::cout << " Invalid Fd don't know what to do" << std::endl;	
					}
    			}/* end of ( conn_id > 0 )*/
  			} /* End of while loop */
		}

	private:
		std::string m_ip;
		std::uint16_t m_port;
		std::string m_path;
		std::int32_t m_udpFd;
		std::int32_t m_serialFd;
		struct sockaddr_in m_toAddr;
		struct termios m_oldConfig;
};

struct TLSServer : public UdpSerial {

	TLSServer(std::string& certificate, std::string& privatekey, const std::string& ip, std::uint16_t port, const std::string& devPort = "/dev/mhitty1") : 
		UdpSerial(ip, port, devPort),
		m_ctx(SSL_CTX_new(TLS_server_method()), SSL_CTX_free), 
		m_ssl(SSL_new(m_ctx.get()), SSL_free) {

		m_certificate = certificate;
		m_privatekey = privatekey;

		/* Set the key and cert */
    	if(SSL_CTX_use_certificate_file(m_ctx.get(), certificate.c_str(), SSL_FILETYPE_PEM) <= 0) {
        	ERR_print_errors_fp(stderr);
        	exit(EXIT_FAILURE);
    	}

    	if(SSL_CTX_use_PrivateKey_file(m_ctx.get(), privatekey.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
        	ERR_print_errors_fp(stderr);
        	exit(EXIT_FAILURE);
    	}

		//attaching plain UDP Fd to SSL Fd
		attachUdpSocket(udp_channel());
	}

	virtual ~TLSServer() {
		SSL_shutdown(m_ssl.get());
	}

	std::int32_t read(std::string& out) {

		std::array<std::uint8_t, 2048> req;
		req.fill(0);

		auto ret = SSL_read(m_ssl.get(), (void *)req.data(), req.size());
		if(ret <= 0) {
			// SSL_read failed
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		out = std::string((const char *)req.data(), ret);
		return(0);
	}

	std::int32_t write(const std::string& in) {

		auto ret = SSL_write(m_ssl.get(), (const void *)in.c_str(), in.length());
		if(ret <= 0) {
			//SSL_write is failed
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		return(0);
	}

	virtual int rxFromUdp(std::string& rsp) override {
		auto result = read(rsp);
		return(result);
	}

	virtual int txToUdp(const std::string& req) override {
		auto result = write(req);
		return(result);
	}

	TLSServer& attachUdpSocket(std::int32_t fd) {
		// This willcause TLS handshake when we do SSL_write if handshake is not already done.
		SSL_set_accept_state(m_ssl.get());
		SSL_set_fd(m_ssl.get(), fd);
		return(*this);
	}

	private:
		std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> m_ctx;
		std::unique_ptr<SSL, decltype(&SSL_free)> m_ssl;
		std::string m_certificate;
		std::string m_privatekey;

};

/**
 * @brief This function takes a pointer to TLSServer and is copied to base class pointer, e.g.
 *         std::unique_ptr<TLSServer> tlsServer = std::make_unique<TLSServer>();
 *		   start_dtls_server(std::move(tlsServer))
 * 
 * @param subject The data is available on subject and willbe delivered to TLSServer
 * @return std::int32_t 
 */
std::int32_t start_dtls_server(std::unique_ptr<UdpSerial> subject) {
	subject->start();
}

struct UDPClient {
	UDPClient(std::string ip, std::uint16_t port) {
		struct sockaddr_in addr;
		/* Set up the address we're going to bind to. */
		::bzero(&addr, sizeof(addr));
  		addr.sin_family      = AF_INET;
  		addr.sin_port        = htons(port);
  		addr.sin_addr.s_addr = inet_addr(ip.c_str());
  		::bzero( &addr.sin_zero, sizeof(addr.sin_zero ) );

		m_udpFd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(m_udpFd < 0) {
			std::cout << "Creation of UDP socket Failed" << std::endl;
			exit(-1);
		}

		/* set the reuse address flag so we don't get errors when restarting */
		auto flag = 1;
		if(::setsockopt(m_udpFd, SOL_SOCKET, SO_REUSEADDR, (std::int8_t *)&flag, sizeof(flag)) < 0 ) {
			std::cout << "Error: Could not set reuse address option on DHCP socket!" << std::endl;
			exit(-1);
		}

		/* bind the socket */
		if(::bind(m_udpFd, (struct sockaddr *)&addr, sizeof(addr) ) < 0) 
		{
			std::cout << "Bind to ip:"<< ip << " port:" << port << " Failed" << std::endl;
			exit(-1);
		}
	}

	~UDPClient() {
		this->close();
	}

	void close() {
		::close(m_udpFd);
	}

	int udp_channel() const {
		return(m_udpFd);
	}

	
	private:
		std::string m_ip;
		std::uint16_t m_port;
		std::int32_t m_udpFd;
		struct sockaddr_in m_toAddr;
};

struct TLSClient : public UDPClient {
	TLSClient(const std::string& ip, std::uint16_t port) : 
		UDPClient(ip, port),
		m_ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free), 
		m_ssl(SSL_new(m_ctx.get()), SSL_free) {

		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();

		//attaching plain UDP Fd to SSL Fd
		attachUdpSocket(udp_channel());
	}

	~TLSClient() {
		SSL_shutdown(m_ssl.get());
	}

	std::int32_t read(std::string& out) {
		std::array<std::uint8_t, 2048> req;
		req.fill(0);

		auto ret = SSL_read(m_ssl.get(), (void *)req.data(), req.size());
		if(ret <= 0) {
			// SSL_read failed
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		out = std::string((const char *)req.data(), ret);
		return(0);
	}

	std::int32_t write(const std::string& in) {
		auto ret = SSL_write(m_ssl.get(), (const void *)in.c_str(), in.length());
		if(ret <= 0) {
			//SSL_write is failed
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		return(0);
	}

	TLSClient& attachUdpSocket(std::int32_t fd) {
		// This willcause TLS handshake when we do SSL_write if handshake is not already done.
		SSL_set_connect_state(m_ssl.get());
		SSL_set_fd(m_ssl.get(), fd);
		return(*this);
	}

	int txToUdp(std::string& req) {
		return(this->write(req));
	}

	int rxFromUdp(std::string& rsp) {
		return(this->read(rsp));
	}

	int start_observer() {
		int conn_id   = -1;
		int num_bytes = -1;
   		fd_set fdList;

 		while (1) {

			/* A timeout for 5 secs*/ 
			struct timeval to;
 			to.tv_sec = 5;
 			to.tv_usec = 0;

		    FD_ZERO(&fdList);
 			FD_SET(udp_channel(), &fdList);
			auto maxFd = udp_channel() + 1;

			conn_id = ::select(maxFd, (fd_set *)&fdList, (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)&to);

			if(conn_id > 0) {

				if(FD_ISSET(udp_channel(), &fdList ) ) {
					std::string request("");
					num_bytes = rxFromUdp(request);
				} else {
					std::cout << " Invalid Fd don't know what to do" << std::endl;	
				}
    		}/* end of ( conn_id > 0 )*/
			return(0);
  		} /* End of while loop */
	}
#if 0
	auto parse_argument_first(auto &&first) {
		std::cout << "value of first: " << first << std::endl;
		return(-1);
	}

	auto parse_argument_many(auto &first, auto &remains...) {
		auto result = parse_argument_first(first);

		if(result < 0) {
			return(0);
		}

		return(parse_argument_many(remains...));
	}

	template <typename... Args>
	std::int32_t process_command(Args... args) {
		parse_argument_many(args...);
		return(0);
	}
#endif
	private:
		std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> m_ctx;
		std::unique_ptr<SSL, decltype(&SSL_free)> m_ssl;
};

/* getopt arguments */
  std::vector<struct option> long_options =
  {
    {"ip",                required_argument, 0, 'i'},
    {"port",              required_argument, 0, 'p'},
    {"role",              required_argument, 0, 'r'},
    {"public-key-file",   required_argument, 0, 'u'},
    {"private-key-file",  required_argument, 0, 'v'},
	{"dev",               required_argument, 0, 'd'},
	{"baudrate",          required_argument, 0, 'b'},
	{"help",              no_argument,       0, 'h'}
  };

int main(int argc, char *argv[]) {
	std::string ip("");
	std::uint16_t port = 0;
	std::string public_key("");
	std::string private_key("");
	std::string role("");
	std::string dev("");
	std::string baudrate("");

	std::int32_t ch;
	// the colon(:) suffix is requred for an option tohave an argument value. In this case h does not requires 
	// any value so nocolon after h.
	while((ch = getopt_long(argc, argv, "i:p:r:u:i:d:b:h", long_options.data(), NULL)) != -1) {
    	switch (ch) {
        	case 'i':
				ip = optarg;
				break;
			case 'p':
				port = std::stoi(optarg);
				break;
			case 'r':
				role = optarg;
				break;
			case 'u':
				public_key = optarg;
				break;
			case 'v':
                private_key = optarg;
                break;
			case 'd':
                dev = optarg;
                break;
			case 'b':
                baudrate = optarg;
                break;
            default:
				std::cout << "Usages: udp_serial --ip=<ip address> --port=<port number> --role=<client/server> "
						  << "--dev=<serial device file name> --public_key=<public key file name> --private_key=<private key file name>";
				break;
     	}
	}

	if(!ip.length() || !port) {
		std::cout << "Invalid argument --ip=<ip address> --port=<port number>" << std::endl;
		return(0);
	}

	if(!dev.length()) {
		dev = "/dev/mhitty1";
	}

	std::string server("server");
	if(role.length() && !role.compare(server)) {
		if(!public_key.length() || !private_key.length()) {
			UdpSerial udp_server(ip, port, dev);
			udp_server.start();
		} else {
			std::unique_ptr<TLSServer> dtls_server = std::make_unique<TLSServer>(public_key, private_key, ip, port, dev);
			start_dtls_server(std::move(dtls_server));
		}
	} else {
		//dtls client
	}
}




















#endif /*__UDP_SERIAL_CPP__*/
