
release : main.cpp
	g++ -std=c++11 main.cpp -lcrypto -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o navicat-keygen

debug : main.cpp
	g++ -std=c++11 -D_DEBUG main.cpp -lcrypto -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o navicat-keygen

clean:
	rm navicat-keygen