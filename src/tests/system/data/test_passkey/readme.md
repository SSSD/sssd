Passkey support is tested with su, tests are running with
umockdev, not with a physical key.

First step is register the key the system administrator uses with sssctl.
The output of this command can be added to the LDAP server in a dedicated attribute for the user.

```sssctl passkey-register --username=<username> --domain=<domain name>```

Next, it will ask for PIN and generate the passkey-mapping and token.

For example:

```
[root@client ~]# sssctl passkey-register --username=joe --domain=ipa.test
Enter PIN:

Please touch the device.
passkey:N5YdS4ZGLS6v7BWYSrvVygRPsvtqTJ9DrAclM5S1C/18axs8XutDEYuKiQrZGwOEpxGsHE1q19A4OOi0bct29g==,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX/gpbrCR/Q+f3CQE9GjVj7Ck+uHl9x5HuacZ+xitqpanwmRzqdu6ls2/CmaOuPs29Sgpi/HZXexW2R5okV4Stg==
```

The output string has `PASSKEY:credentialId,publicKey` format.

umockdev mocks Linux devices for creating integration tests for hardware related libraries and programs.
It also provides tools to record the properties and behaviour of particular devices, and to run a program
or test suite under a test bed with the previously recorded devices loaded.

umockdev consists of the following parts:

- The `umockdev-record` program generates text dumps (conventionally called *.umockdev) of some specified,
  or all of the system's devices and their sysfs attributes and udev properties.
- The `libumockdev-preload` library intercepts access to /sys, /dev/, /proc/, the kernel's netlink socket (for uevents)
  and ioctl() and re-routes them into the sandbox built by libumockdev.
- The `umockdev-run` program builds a sandbox using libumockdev, can load *.umockdev, *.ioctl, and *.script files
  into it, and run a program in that sandbox.

We need device file, to create it we use following command,

```HIDRAW=$(fido2-token -L|cut -f1 -d:)```

```umockdev-record $HIDRAW > /tmp/umockdev.device```

We need `random.so` as an `LD_PRELOAD` while creating the recording files, `random.so` is created by compiling [random.c](https://github.com/SSSD/sssd-ci-containers/tree/master/src/ansible/roles/passkey/files).

```gcc -fPIC -shared -o random.so random.c -lcrypto```

Above `gcc` command is being used to compile `random.c` file.

We use following command to create the recording files, passkey is connected and after entering the correct PIN, it will blink to touch and then it will create the recording files.

```
LD_PRELOAD=/opt/random.so umockdev-record --script ${HIDRAW}=/tmp/umockdev.script --ioctl ${HIDRAW}=/tmp/umockdev.ioctl -- bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> /etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; su - ci -c "su - user1 -c whoami"'
Insert your passkey device, then press ENTER.
Enter PIN:
su: warning: cannot change directory to /home/user1: Permission denied
-sh: /home/user1/.profile: Permission denied
user1
```

The above command create `/tmp/umockdev.script` and `/tmp/umockdev.ioctl`, those will be use in `umockdev-run` command to check authentication without touch the passkey.

To test, we use following command, here passkey did not blink to touch nor we are touching the key,

```
LD_PRELOAD=/opt/random.so umockdev-run --device /tmp/umockdev.device --script ${HIDRAW}=/tmp/umockdev.script --ioctl ${HIDRAW}=/tmp/umockdev.ioctl -- bash -c 'env | grep ^UMOCKDEV_ > /etc/sysconfig/sssd; printf "LD_PRELOAD=$LD_PRELOAD" >> /etc/sysconfig/sssd; systemctl restart sssd; chmod -R a+rwx $UMOCKDEV_DIR; date ; su - ci -c "su - user1 -c whoami"'
Insert your passkey device, then press ENTER.
Enter PIN:
user1
```