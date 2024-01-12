#!/bin/bash
set -eu -o pipefail

entrypoint_c() (
cat<<'EOF'
#define _GNU_SOURCE
#include <sys/types.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

char *dirs[] = {"/home/chronos/user/.bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", NULL};
char dirname[PATH_MAX + 1] = "";

char bind_errors = 0;
int bind(char *path, char *mountpoint) {
        if (mount(path, mountpoint, "bind", MS_BIND | MS_PRIVATE | MS_REC, NULL)) {
                fprintf(stderr,"bind(%s, %s): %s\n", path, mountpoint, strerror(errno));
                bind_errors = 1;
                return -1;
        }

        return 0;
}

int main(int argc, char **argv) {
        ssize_t len = readlink("/proc/self/exe", dirname, sizeof(dirname) - 1);
        if (len != -1) {
                dirname[len] = '\0';
                char *base = strrchr(dirname, '/');
                if (base == NULL) len = 1;
                else len -= strlen(base);
                dirname[len] = '\0';
        }

        if (unshare(CLONE_NEWNS)) {
                perror("unshare");
                exit(1);
        }

        char wd_dir[PATH_MAX];
        getcwd(wd_dir, sizeof(wd_dir));

        chdir(dirname);

        bind("mnt", "/mnt");
        bind("/usr/local", "/mnt/local");
        bind("usr", "/usr");
        bind("/mnt/local", "/usr/local");
        //bind("/var/run/chrome", "/mnt/chrome");
        //bind("/var/run/crosdns", "/mnt/crosdns");
        //TODO my_files
        //bind("/run/chrome/local", "/run");
        //bind("/mnt/run", "/run");
        bind("bin", "/bin");
        bind("etc", "/etc");
        bind("home", "/home");
        bind("lib", "/lib");
        bind("sbin", "/sbin");
        bind("var", "/var");
        bind("root", "/root");
        bind("opt", "/opt");
        bind("lib64", "/lib64");

        mount("", "/var/run", "", MS_REMOUNT & ~MS_NOEXEC, NULL);
        mount("", "/tmp", "", MS_REMOUNT & ~MS_NOEXEC, NULL);

        if (bind_errors) {
                exit(2);
        }

        char *args[1024];
        int ind, start = 0;
        char *argv0 = strrchr(argv[0], '/');
        if (argv0) argv0++;
        else argv0 = argv[0];

        if (strcmp(argv0, "entrypoint") == 0) {
                start++;
        }

        for (ind = 0; ind < argc - start; ind++) args[ind] = argv[ind + start];
        args[ind] = NULL;

        chdir(wd_dir);

        ind = 0;
        char *dir;
        while ((dir = dirs[ind++])) {
                char *path;
                asprintf(&path, "%s/%s", dir, args[0]);
                execv(path, args);
        }

        perror(args[0]);

        exit(3);
}
EOF
)

if [ "$(id -u)" -ne 0 ]; then
        echo "fatal: script must be run as root" 
        exit 1
fi

umount_dirs() {
        umount $DIR/dev/pts $DIR/dev $DIR/proc $DIR/tmp $DIR/run $DIR/sys 
}

cleanup() {
        set +eu +o pipefail
        trap '' HUP INT TERM ERR
        echo "installation aborted" 
        umount_dirs
        rm -fr "$ORIGDIR"
        exit 1
}

readonly ORIGIN="https://dl-cdn.alpinelinux.org" \
        PATHNAME="/alpine/latest-stable/releases/$(uname -m)"

readonly ORIGDIR="$(TMPDIR="/usr/local" mktemp -dt bootstrap.XXXX)"
trap cleanup HUP INT TERM ERR

chmod 755 "$ORIGDIR"
chown 1000:1000 "$ORIGDIR"

readonly DIR="$ORIGDIR/rootfs"
mkdir "$DIR"

echo "downloading rootfs"

readonly LATEST_RELEASES_URI="${ORIGIN}/${PATHNAME}/latest-releases.yaml"
readonly ROOTFS_URI="${ORIGIN}/${PATHNAME}/$(curl --progress-bar "${LATEST_RELEASES_URI}"  | grep -F 'file: alpine-minirootfs' | tr -d '[:blank:]' | cut -d ':' -f 2)"

cd "$DIR"
curl --progress-bar "${ROOTFS_URI}" --output -  | tar -x -zgz -f-

echo done

rm -fr home media mnt srv opt dev proc sys tmp root run etc/resolv.conf

entrypoint_c > entrypoint.c

cat <<'EOF' | chroot . /bin/sh
set -eu
mkdir -p /dev /proc /sys /tmp /run
mkdir -p /mnt/local /mnt/my_files /mnt/downloads /mnt/chrome /mnt/crosdns /mnt/empty /opt /lib64 
chmod 777 /tmp
echo 'devtmpfs /dev devtmpfs rw,mode=755 0 0' > /etc/fstab
echo 'devpts /dev/pts devpts rw,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0' >> /etc/fstab
echo 'tmpfs /tmp tmpfs rw,exec,suid,uid=1000,gid=1000' >> /etc/fstab
echo 'tmpfs /run tmpfs rw,exec,suid,uid=1000,gid=1000' >> /etc/fstab
echo 'none /sys sysfs rw' >> /etc/fstab
echo 'proc /proc proc rw' >> /etc/fstab
mount -a
echo 'nameserver 1.1.1.1' > etc/resolv.conf
export HOME=/tmp
packages="musl-dev gcc bash patchelf micro joe sudo findutils git wget less sed net-tools curl gawk util-linux shadow coreutils psutils libcap-utils binutils"

echo "installing packages"
while ! apk update ; do 
        echo retrying...
done
while ! apk add $packages -q --progress  --timeout 3 ; do
        echo retrying...
done
echo  done

echo 'chronos:x:1000:1000:,,,:/home/chronos/user:/bin/bash' >> /etc/passwd
echo 'chronos-access:!:1001:1001:,,,:/home/chronos:/bin/false' >> /etc/passwd
echo 'chronos:!:1000:' >> /etc/group
echo 'chronos-access:!:1001:chronos' >> /etc/group
echo 'chronos:!:1:0:99999:7:::' >> /etc/shadow
echo 'chronos-access:!::0:::::' >> /etc/shadow
mkdir -p /home/chronos/user
chown 1000:1000 /home/chronos/user
chmod 0700 /home/chronos/user
mkdir -p /root
chmod 07000 /root
echo 'chronos ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/chronos

echo "compiling entrypoint"

gcc -x c -static -o /entrypoint /entrypoint.c
setcap =ep /entrypoint

echo done

EOF

cp entrypoint* $ORIGDIR

echo "creating archive"

readonly IMAGE_FILENAME="$ORIGDIR/rootfs-base.tar.gz"
tar --one-file-system -cf "$IMAGE_FILENAME" . 

chown 1000:1000 "$IMAGE_FILENAME"
echo -e -n "\r$IMAGE_FILENAME\n"

umount_dirs || true

echo "done"
