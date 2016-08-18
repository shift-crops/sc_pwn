// gcc -m32 -fstack-protector-all echo.c -o echo
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <signal.h>

#define PORTNUM 8080 
#define BUFSIZE 512

void set_sighandler(int, void*);
void wait_child(int);
void echo(int);

int main(int argc, char* argv[])
{
	struct sockaddr_in	saddr, caddr;
	int			fd1, fd2, len, id=0;
	const int 		on = 1;

	set_sighandler(SIGCHLD, wait_child);

	/* make server's socket */
	if ((fd1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return -1;
	}
	setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family      = AF_INET;
	saddr.sin_port        = htons(argc>1?atoi(argv[1]):PORTNUM);
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(fd1, (struct sockaddr*)&saddr, sizeof(saddr))) {
		perror("bind");
		return -1;
	}

	if(listen(fd1, 5)) {
		perror("listen");
		return -1;
	}

	while(1) {
		if((fd2 = accept(fd1, (struct sockaddr*)&caddr, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		else
			id++;

		switch(fork()){
			case 0:
				close(fd1);

				fprintf(stdout,"Connect : [%02d]\n",id);
				echo(fd2);
				dprintf(fd2,"Bye!\n");
				fprintf(stdout,"Disconnect : [%02d]\n",id);
				shutdown(fd2, SHUT_RDWR);
				close(fd2);
				exit(0);
			case -1:
				perror("child process");
				break;
			default:
				close(fd2);	
		}
	}
	
	shutdown(fd1, SHUT_RDWR);
	close(fd1);	
	return 0;
}

void echo(int fd){
	char	buf[BUFSIZE]={0};
	int	len;

	dprintf(fd,"Welcome to Echo Server\nInput your message\n>>");
	len = recv(fd, buf, BUFSIZE*2,0);

	dprintf(fd,"Okay! I recieved %d bytes\n%s\n",len,buf);
}

void set_sighandler(int signum,void *func){
	struct sigaction act;

	memset(&act, 0, sizeof(act));

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_NOCLDSTOP | SA_RESTART;

	sigaction(signum, &act, NULL);
}

void wait_child(int signo){
	int child_ret;
	while(waitpid(-1, &child_ret, WNOHANG)>0);
}
