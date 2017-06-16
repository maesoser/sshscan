# sshscan

Multithreaded ssh scanner for networks

## How to compile it

You need to install `libssh-dev`. After that, you can just invoque `make`

## How to use it

```
sshscan [OPTIONS] [USER_PASSW FILE] [IP RANGE]
```

**Options** are:

- `-t [NUMTHREADS]`: Change the number of threads used. Default is 32.
- `-p [PORT]`: Specify another port to connect to.
- `-h` : Show this help.
- `-v` : Verbose mode.

**Examples**
```
.\sshscan userpasswdfile 192.168.0.0/24
```

```
.\sshscan -t 128 -v userpasswd 192.168.0.0/24
```
## Other tools you should check

Like [THC-Hydra](https://www.thc.org/thc-hydra/), [Ncrack](https://nmap.org/ncrack/) or [Medusa](http://foofus.net/goons/jmk/medusa/medusa.html). The same brute force attack we did on the upper section could be done with this tools:

```
hydra -C userpasswdfile 192.168.0.0/24 ssh
```

```
ncrack -p 22 -U userfile -P passwdfile  192.168.0.0/24
```

```
medusa -C userpasswdfile -h  192.168.0.0/24 -M ssh
```

## Acknowledgements

- [**libssh**](https://www.libssh.org/)
- [**Pithiko's Thread Pool**](https://github.com/Pithikos/C-Thread-Pool)

## Things you should know

```
#As root or via sudo, type this to see all failed login attempts
cat /var/log/auth.log | grep 'sshd.*Invalid'

#If you want to see successful logins, type this
cat /var/log/auth.log | grep 'sshd.*opened'
```
