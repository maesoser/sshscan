# sshscan

Multithreaded ssh scanner for networks

## How to compile it

You need to install `libssh-dev`. After that, you can just invoque `make`

## How to use it

This is going to change, probably.

```
sshscan [IP]/[MASK] [USER-PASSWD] [THREADS]
```

## Acknowledgements

- [**libssh**](https://www.libssh.org/)
- [Pithiko's Thread Pool](https://github.com/Pithikos/C-Thread-Pool)

## Things you should know

```
#As root or via sudo, type this to see all failed login attempts
cat /var/log/auth.log | grep 'sshd.*Invalid'

#If you want to see successful logins, type this
cat /var/log/auth.log | grep 'sshd.*opened'
```
