#### [@bradbaris](https://github.com/bradbaris): Completed these for the trivia. Networking knowledge is evergreen.  


Linux System Administrator/DevOps Interview Questions
====================================================

A collection of linux sysadmin/devops interview questions. Feel free to contribute via pull requests, issues or email messages.


## <a name='toc'>Table of Contents</a>

  1. [Contributors](#contributors)
  1. [General Questions](#general)
  1. [Simple Linux Questions](#simple)
  1. [Medium Linux Questions](#medium)
  1. [Hard Linux Questions](#hard)
  1. [Expert Linux Questions](#expert)
  1. [Networking Questions](#network)
  1. [MySQL Questions](#mysql)
  1. [DevOps Questions](#devop)
  1. [Fun Questions](#fun)
  1. [Demo Time](#demo)
  1. [Other Great References](#references)


#### [⬆](#toc) <a name='contributors'>Contributors:</a>

* [moregeek](https://github.com/moregeek)
* [typhonius](https://github.com/typhonius)
* [schumar](https://github.com/schumar)
* [negesti](https://github.com/negesti)
* peter
* [andreashappe](https://github.com/andreashappe)
* [quatrix](https://github.com/quatrix)
* [biyanisuraj](https://github.com/biyanisuraj)
* [pedroguima](https://github.com/pedroguima)
* Ben


#### [⬆](#toc) <a name='general'>General Questions:</a>

* What did you learn yesterday/this week?
  - **[...]**
* Talk about your preferred development/administration environment. (OS, Editor, Browsers, Tools etc.)
  - **MacOS, SublimeText or Vim, Chrome, Bash and ZSH, etc.**
* Tell me about the last major Linux project you finished.
  - **[...]**
* Tell me about the biggest mistake you've made in [some recent time period] and how you would do it differently today. What did you learn from this experience?
  - **[...]**
* Why we must choose you?
  - **[...]**
* What function does DNS play on a network?
  - **Domain Name System (DNS) is essentially a map that resolves hostnames to IP addresses. It also stores records for specific services, such as email.**
* What is HTTP?
  - **Hypertext Transfer Protocol (HTTP), an application-layer protocol in a client-server model, for communicating in hypertext. Hypertext refers to interactive text on the web. It is the protocol on which the internet (WWW) is founded on.**
* What is an HTTP proxy and how does it work?
  - **A HTTP proxy is simply an intermediary server that receives your HTTP requests and then forwards the request to the destination server on your behalf, masking your identity while returning the results to your browser.**
* Describe briefly how HTTPS works.
  - **HTTPS is the secure version of HTTP, using SSL/TLS (actually just TLS nowadays) to encrypt communications. SSL/TLS use an asymmetric Public Key Infrastructure (PKI) system, which uses two keys for encryption, a public key and a private key. Anything encrypted with the public key can only be decrypted by the private key and vice-versa. When one requests a HTTPS connection to a website, it will transmit its SSL certificate (which contains its public key) to your browser. After this exchange, your browser and the website will initiate a 'SSL/TLS handshake'. The handshake involves the generation of shared secrets to establish a uniquely secure connection between yourself and the website.**
* What is SMTP? Give the basic scenario of how a mail message is delivered via SMTP.
  - **Simple Mail Transfer Protocol (SMTP) is an application-layer protocol for email transmission. Mail sent over SMTP is initiated by the user's SMTP client connecting to an SMTP server, transferring the sender's information (MAIL), recipient's address (RCPT), and email message (DATA). The SMTP server then locates the recipient, parsing out the TLD of the recipient's email, using DNS. The SMTP server then sends the email data to the SMTP server of the recipient, where it is later processed and delivered via POP3 or IMAP.**
* What is RAID? What is RAID0, RAID1, RAID5, RAID10?
  - **RAID originally stood for 'redundant array of inexpensive disks', now commonly known as 'redundant array of independent disks'. It combines multiple hard drive components into a single unit for data redundancy and/or performance purposes.**
  - **RAID0 - This configuration is known as 'striping', where data is split up and written across all drives in the array. This offers superior I/O at the cost of being very fault-intolerant— if one drive fails, all data is lost.**
  - **RAID1 - This configuration is known as 'mirroring', where data is stored twice, in two different drives as a form of backup and redundancy. If one drive fails, there is another copy of the data on the other drive.**
  - **RAID5 - This configuration is known as 'striping with parity', where data blocks are striped across all drives, but a parity checksum of those blocks are also written to a drive. These parity checksums are spread across all drives for safety, in case of drive failure. If a drive does fail, the missing data block can be reconstructed using the parity data and the rest of blocks. If the lost drive contained the parity data, then it can simply be recalculated, like a checksum.**
  - **RAID10 - This configuration combines RAID1 and RAID0, hence RAID10. This method has multiple sets of drives, where each set has data striped across its drives. This system is then mirrored onto another set for redundancy. This has the advantages of I/O speeds and redundancy, but half of the storage capacity goes into mirroring, so it can be costly.**
* What is a level 0 backup? What is an incremental backup?
  - **A level 0 backup, is essentially a 'full backup', but in the context of an incremental backup strategy. It copies all blocks containing data, and serves as the base backup on which all subsequent incremental backups are built upon. An incremental backup is a backup that only stores the blocks changed after the last backup.**
* Describe the general file system hierarchy of a Linux system.
  - **The file system in Linux begins with the root directory `/`, from which all files and folders stem from. Other partitions and resources can be mounted as a volume onto this rooted tree. Also somewhat related: in Linux, "everything is a file", so everything from processes, files, directories, sockets, pipes, et cetera can be accessed like a file (or more accurately, they are represented by a file descriptor abstracted over the virtual filesystem layer in the kernel).**

#### [⬆](#toc) <a name='simple'>Simple Linux Questions:</a>

* What is the name and the UID of the administrator user?
  - **The `root` user, with an UID of 0.**
* How to list all files, including hidden ones, in a directory?
  - **`ls -A`**
* What is the Unix/Linux command to remove a directory and its contents?
  - **`rm -Rf somedir/`**
* Which command will show you free/used memory? Does free memory exist on Linux?
  - **`free` or `top` or `df -h`. Any free memory in Linux may be perpetually utilized for buffering and/or caching, along with swap space, so it is possibly deployed in some way at any time.** 
* How to search for the string "my konfi is the best" in files of a directory recursively?
  - **`grep -Rn "my konfi is the best" *` (the `-n` flag is to show line numbers, for convenience)**
* How to connect to a remote server or what is SSH?
  - **Secure Shell (SSH) is a cryptographic network protocol for operating network services securely over an unsecured network. The best known example application is for remote login to computer systems by users.**
* How to get all environment variables and how can you use them?
  - **`printenv` or `env`. Environment variables can be used to modify the context of running processes, and/or be referenced to access properties of your current session.**
* I get "command not found" when I run ```ifconfig -a```. What can be wrong?
  - **One potential reason could be that `sbin/` is not included in the `PATH` environmental variable. `ifconfig` is usually located in `sbin/`.**
* What happens if I type TAB-TAB?
  - **If you are typing a command, it will bring up autocompletion for commands that match the string currently input. If on the second argument for a command, it will list the directory/files.**
* What command will show the available disk space on the Unix/Linux system?
  - **`df`**
* What commands do you know that can be used to check DNS records?
  - **`nslookup` or `host` or `dig`**
* What Unix/Linux commands will alter a files ownership, files permissions?
  - **`chown` and `chgrp` and `chmod`**
* What does ```chmod +x FILENAME```do?
  - **It gives `execute` rights to everyone (owner, group, world)**
* What does the permission 0750 on a file mean?
  - **The owner of the file has `rwx` permissions (read, write, execute), and the group has `rx` permissions (read, execute). The file is off-limits to everyone else.**
* What does the permission 0750 on a directory mean?
  - **On a directory, this means that only the owner has full permissions to do anything with its contents; the group read and execute but cannot write to the folder; the rest of the world cannot do anything at all with the folder.**
* How to add a new system user without login permissions?
  - **`useradd -r username` The `-r` flag will create a system user, which does not have a password or a home directory, and is unable to login.**
* How to add/remove a group from a user?
  - **To add a group, `usermod -a -G groupname username`. To remove a group, one can simply omit the group from the comma-delimited `groupname` param in the same command above. Alternatively, one could simply use `gpasswd -d username groupname` is `gpasswd` is available.**
* What is a bash alias?
  - **A bash alias is simply a shortcut to a command or a function.**
* How do you set the mail address of the root/a user?
  - **Modify the `/etc/aliases` file, and add something like `root: your@email.com`, then run `newaliases` to update.** 
* What does CTRL-c do?
  - **It kills the foreground (current) process by sending a `SIGINT` signal.**
* What is in /etc/services?
  - **`/etc/services` maps port numbers to named services. It makes it easier for processes to figure out what programs use what port number and whether it is TCP/UDP.**
* How to redirect STDOUT and STDERR in bash? (> /dev/null 2>&1)
  - **`STDOUT` can be redirected with `>` or `1>`, and `STDERR` can be redirected with `2>`. To redirect them both to `STDOUT`, one can use `2>&1`. Note that `>` overwrites, and `>>` appends. `> /dev/null 2>&1` redirects both to the void.**
* What is the difference between UNIX and Linux.
  - **UNIX is a copyrighted brand name, Linux is an opensource UNIX clone. They are both POSIX-compliant.**
* What is the difference between Telnet and SSH?
  - **The main difference is that SSH uses encryption for secure communications. Telnet was designed for use within private networks, and transmits in plain text.**
* Explain the three load averages and what do they indicate. What command can be used to view the load averages?
  - **The three numbers represent the system load during the last one-, five-, and fifteen-minute periods. `uptime` and `top` can be used to view load averages.**
* Can you name a lower-case letter that is not a valid option for GNU ```ls```?
  - **`-y`**

#### [⬆](#toc) <a name='medium'>Medium Linux Questions:</a>

* What do the following commands do and how would you use them?
  * ```tee```
    - **Splits the output of a program into two destinations, typically used to save a file and display to terminal at the same time. Example: `ls -l | tee file.txt | less` pipes the directory listing into both `file.txt` and `less`**
  * ```awk```
    - **Pattern scanning and processing language. Example: If it were given a tab-delimited file named `file.txt`, and you wanted to print out only the 3rd and 4th columns, you could type `awk '{print $3 "\t" $4}' file.txt`**
  * ```tr```
    - **A translate or transliterate tool, able to replace/remove specific characters in its input data set. Example: ROT13, a special Caesar cipher, can be done with `tr '[A-Za-z]' '[N-ZA-Mn-za-m]'`**
  * ```cut```
    - **Cuts out selected portions of each line of a file and writes it to `STDOUT`. Example: `pwd | cut -c 1-10` cuts the first 10 char of the current directory path.**
  * ```tac```
    - **Concatenate and print files in reverse (think of `cat` backwards). Example: `tac file1.txt` prints the lines of `file1.txt` in reverse, from last line to first.**
  * ```curl```
    - **Transfer data to or from a server, typically over HTTP, but also supports many other protocols.`curl -L https://www.google.com` will request Google (and follow redirects in doing so).**
  * ```wget```
    - **Non-interactive downloader of files from network/WWW. Example: `wget https://www.google.com/robots.txt` will download `robots.txt`.**
  * ```watch```
    - **Runs a command repeatedly on a specified interval, displaying its output. Example: `watch -d ls -l` will watch for changes in the contents of the current directory.**
  * ```head```
    - **Display first lines of a file. Example: `head -n 1 robots.txt` will return only the first line of `robots.txt`**
  * ```tail```
    - **Display last lines of a file. Example: `tail -n 1 robots.txt` will return only the last line of `robots.txt`**
* What does an ```&``` after a command do?
  - **The shell executes the command in the background in a subshell. The shell does not wait for the command to finish, and the return status is 0.**
* What does ```& disown``` after a command do?
  - **`&` puts the process into the background, and `disown` removes the process from the shell's job control, but it still leaves it connected to the terminal.**
* What is a packet filter and how does it work?
  - **Otherwise known as a firewall. Packet filters control network access by monitoring outgoing and incoming packets and allowing them to pass or halt based on the source and destination IP addresses, protocols and ports.**
* What is Virtual Memory?
  - **A mix of both RAM and swap space combined to give an application the illusion that it has contiguous working memory.**
* What is swap and what is it used for?
  - **Swap is hard disk drive space that is used for virtual memory. Inactive pages can be stored temporarily in swap to optimize performance when RAM.**
* What is an A record, an NS record, a PTR record, a CNAME record, an MX record?
  - **The `A` record maps a name to one or more IP addresses, when the IP are known and stable.**
  - **The `NS` record stands for 'name servers', and specifies the DNS servers for your domain.**
  - **The `PTR` record is the opposite of the `A` record. The `PTR` record resolves the IP address to a domain/hostname.**
  - **The `CNAME` record maps a name to another name. It should only be used when there are no other records on that name.**
  - **The `MX` record stands for 'mail exchange'. `MX` records tell email delivery agents where they should deliver your email.**
* Are there any other RRs and what are they used for?
  - **The `AAAA` record is the `A` record for IPv6. It maps a hostname to a 128-bit IPv6 address.**
  - **The `CAA` record stands for 'Certification Authority Authorization', and is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.**
  - **The `TXT` record associates some arbitrary and unformatted text with a host and provides that information to sources outside your domain.**
  - **The `SOA` record stands for 'Start of Authority' and is used to determine how your zone propagates to secondary nameservers. Every domain must have a `SOA` record at the cutover point where the domain is delegated from its parent domain, and there should only be one of its kind.**
  - **The `SPF` record stands for 'Sender Policy Framework', and is used to indicate to mail exchanges which hosts are authorized to send mail for a domain.**
  - **The `SRV` records are used to help with service discovery. It defines a symbolic name and the transport protocol used for that service, as part of the domain name, and defines the priority, weight, port and target for that service as well.**
  - **The `NAPTR` records stands for 'Naming Authority Pointer' and are related to `SRV` records in associating services rules, and support regular expression based rewriting.**
  - **The `HINFO` record specifies the host/server's type of CPU hardware and operating system.**
  - **The `SSHFP` record stands for 'Secure Shell (Key) Fingerprint' and contains fingerprints for public keys used for SSH. They're mostly used with DNSSEC enabled domains.**
* What is a Split-Horizon DNS?
  - **Split horizon is the ability for a DNS to give a different response to a query based on the source of the query. Example: Using the same DNS server for internal and external queries.**
* What is the sticky bit?
  - **The sticky bit is a special file permission that can be assigned to files and directories on Unix-like systems. When a directory's sticky bit is set, the files within can only be renamed or deleted by the file's owner, the directory's owner, or `root`. Example: `sudo chmod +t /tmp` and `sudo chmod -t /tmp`**
* What does the immutable bit do to a file?
  - **The immutable bit makes a file unable to be deleted or renamed; no link can be created to this file and no data can be written to the file— even `root` cannot erase or edit the file. `root` is the only user who can set or clear this bit.**
* What is the difference between hardlinks and symlinks? What happens when you remove the source to a symlink/hardlink?
  - **Underneath the filesystem, files are represented by inodes. A hardlink simply just creates another file with a link to the same underlying inode. A symlink is just another link to the file.**
* What is an inode and what fields are stored in an inode?
  - **An inode is a data structure which describes a filesystem object such as a file or a directory and points to it. Each inode stores the attributes and disk block location(s) of the object's data. Filesystem object attributes may include metadata (times of last changed, access, modification, etc), as well as owner and permission data.**
* How to force/trigger a file system check on next reboot?
  - **Create an empty file `/forcefsck` in the root `/` directory.**
* What is SNMP and what is it used for?
  - **Simple Network Management Protocol. It is used for network management: collecting information from, and configuring, network devices, such as servers, printers, hubs, switches, and routers, et cetera.**
* What is a runlevel and how to get the current runlevel?
  - **A runlevel is a preset operating state, and represented by a single digit integer. Each runlevel designates a different system configuration and levels of access to different combinations of processes. 'Safe Mode' on Windows would be the equivalent of runlevel 1. Current runlevel can be found with `who -r`**
* What is SSH port forwarding?
  - **SSH port forwarding is also known as TCP/IP connection tunneling, which is a process where an insecure connection is tunneled through SSH, thus protecting the tunneled connection from network attacks. Port forwarding can be used to establish a form of a virtual private network (VPN).**
* What is the difference between local and remote port forwarding?
  - **Local port forwarding creates an outgoing tunnel which can be used to bring a public internet computer to local machine. Remote port forwarding creates an incoming tunnel which can be used to bring a local computer into the public internet.**
* What are the steps to add a user to a system without using useradd/adduser?
  - **Add a new record for the user in `/etc/passwd`, using `sudo vipw`. Refer to documentation for syntax.**
  - **Add a new record for the user in `/etc/shadow`, using `sudo vipw -s`. Refer to documentation for syntax.**
  - **Add a new record for the user in `/etc/group`, using `sudo vigr`. Refer to documentation for syntax.**
  - **Add a new record for the user in `/etc/gshadow`, using `sudo vigr -s`. Refer to documentation for syntax.**
  - **Create and populate a home directory for the new user, `/home/username`. Copy `/etc/skel` as a template.**
  - **Set appropriate permissions and ownership to the `home` directory.**
* What is MAJOR and MINOR numbers of special files?
  - **The major number identifies the driver associated with the device. The minor number is used by the kernel to determine exactly which device is being referred to. It is entirely up to the driver how the minor number is being interpreted.**
* Describe the mknod command and when you'd use it.
  - **The `mknod` command creates the character and block devices that live in `/dev/`. The `mknod` command needs as input: a device name, device type (`c` or `b`), major/minor number, and unit/subunit. If for some reason, something happens to `dev/` (likely a catastrophe), then `mknod` can be used to repopulate the devices. This is an extremely rare case.**
* Describe a scenario when you get a "filesystem is full" error, but 'df' shows there is free space.
  - **The filesystem can run out of inodes, `df -i` will show that.**
* Describe a scenario when deleting a file, but 'df' not showing the space being freed.
  - **Deleting the filename doesn't actually delete the file. Some other process may be holding the file open, causing it to not be deleted, so that process needs to be restarted or killed to release the file lock. `lsof +L1` can be used to find that process.**
* Describe how 'ps' works.
  - **The `ps` command stands for 'process status' and it works by reading files in the proc filesystem (procfs). The directory `/proc/<PID>` contains various files that provide information about process PID. The content of these files is generated on the fly by the kernel when a process reads them.**
* What happens to a child process that dies and has no parent process to wait for it and what's bad about this?
  - **It becomes what is known as a zombie process, where the process has already terminated but is still on the process table. This is bad because the resources for it are not deallocated until it is properly 'reaped' and could cause a resource leak.**
* Explain briefly each one of the process states.
  - **`I` - Marks a process that is idle (sleeping for longer than about 20 seconds).**
  - **`R` - Marks a runnable process.**
  - **`S` - Marks a process that is sleeping for less than about 20 seconds.**
  - **`T` - Marks a stopped process.**
  - **`U` - Marks a process in uninterruptible wait.**
  - **`Z` - Marks a dead process, also known as a zombie.**
* How to know which process listens on a specific port?
  - **`lsof -i :<port>`**
* What is a zombie process and what could be the cause of it?
  - **See above for definition. Issues with zombie processes are indicative of either a system issue or an application issue.**
* You run a bash script and you want to see its output on your terminal and save it to a file at the same time. How could you do it?
  - **Using `ls` as an example: `ls -l | tee <filename> | less`**
* Explain what `echo "1" > /proc/sys/net/ipv4/ip_forward` does.
  - **Enable IP forwarding, although the setting doesn't persist after reboot. This could also be done with `sysctl -w net.ipv4.ip_forward=1`**
* Describe briefly the steps you need to take in order to create and install a valid certificate for the site https://foo.example.com.
  - **Create a 'Certificate Signing Request' (CSR), with OpenSSL: `openssl req -new -newkey rsa:2048 -nodes -keyout example.key -out example.csr` and input `foo.example.com` as the Common Name.**
  - **Verify the CSR with: `openssl req -noout -text -in example.csr`**
  - **Request the SSL certificate from your certificate authority (CA).**
  - **Install the SSL certificate. Copy all the contents of the certificate, including the `BEGIN CERTIFICATE` and `END CERTIFICATE` lines, and save it as `example.crt`. Next, copy the certificate and private key into the server, wherever certificates are stored. Then, change the server config to include the new certificate file and key.**
* Can you have several HTTPS virtual hosts sharing the same IP?
  - **Yes, using Server Name Indication (SNI), which sends a site visitor the certificate that matches the requested server name. The virtual host file(s) has to be reconfigured for this.**
* What is a wildcard certificate?
  - **A wildcard certificate is a public key certificate which can be used with multiple or all possible subdomains of a domain, like `*.example.com`**
* Which Linux file types do you know?
  - **There are regular files, directories, device/special files, links, named pipes, and sockets.**
* What is the difference between a process and a thread? And parent and child processes after a fork system call?
  - **The difference between processes and threads is that threads (of the same process) run in a shared memory space, while processes run in separate memory spaces.**
  - **When a process calls fork, it is deemed the parent process and the newly created process is its child. After the fork, both processes not only run the same program, but they resume execution as though both had called the system call.**
* What is the difference between exec and fork?
  - **`fork` will create a new process that is exactly the same as the parent process. This means the entire state is copied, including open files, register state and all memory allocations, which includes the program code.**
  - **`exec` will create a new process that is not part of the same program as its parent process. `exec` will replace the contents of the currently running process with the new process.**
* What is "nohup" used for?
  - **`nohup` disconnects the process from the terminal, redirects its output to `nohup.out` and shields it from `SIGHUP` (the `HUP` 'hangup' signal). `nohup` is used when you want to prevent a process from being killed when its session ends. Also, see `tmux`.**
* What is the difference between these two commands?
  * ```myvar=hello```
  * ```export myvar=hello```
    - **The first one means that the variable scope is restricted to the shell, and is not available to any other process. The `export` means that the variable name is available to any (sub)process you run from that shell.**
* How many NTP servers would you configure in your local ntp.conf?
  - **Three. First would be the closest timeserver, second would be another as a backup, and third would be the local clock, with the pseudo IP (`127.127.1.0`)**
* What does the column 'reach' mean in ```ntpq -p``` output?
  - **The `reach` field is a circular bit buffer. It gives you the status of the last eight NTP messages, usually `377`, which means all 8 responses from the server were received. `377` is eight bits in octal, `377 = 1 1 1 1 1 1 1 1`**
* You need to upgrade kernel at 100-1000 servers, how you would do this?
  - **Perhaps use Puppet/Chef/Ansible/Salt/CFEngine and update them on a distributed schedule, and depending on the upgrade severity, enable automatic upgrades.**
* How can you get Host, Channel, ID, LUN of SCSI disk?
  - **`cat /proc/scsi/scsi | grep scsi`**
* How can you limit process memory usage?
  - **`ulimit -v <number>` (number should be in 1024-byte increments), or even `cgroups`**
* What is bash quick substitution/caret replace?
  - **`^x^y` (replaces x with y)**
* Do you know of any alternative shells? If so, have you used any?
  - **Besides the Bourne shell (`sh`), I've heard of `fish`, `ksh`, `csh` and `tcsh`, `zsh`. I only use `bash` and `zsh`.**
* What is a tarpipe (or, how would you go about copying everything, including hardlinks and special files, from one server to another)?
  - **`(cd src && tar -cf - .) | (cd dest && tar -xpf -)` - This basically copies over one directory to another, `src` to `dest`, compressing it in the process to reduce the transfer size.**

####[[⬆]](#toc) <a name='hard'>Hard Linux Questions:</a>

* What is a tunnel and how you can bypass a http proxy?
  - **A tunnel (also known as a port forward) is a method of transmitting data over the network, wrapped in a secure connection. By wrapping one kind of data traffic in another kind of traffic on another port, one can disguise its origin and bypass network filters.**
* What is the difference between IDS and IPS?
  - **Intrusion Detection Systems (IDS) passively monitor packet traffic on the network, comparing the traffic to configured rules, and setting off an alarm if it detects any known threats.**
  - **Intrusion Prevention Systems (IPS) sit inline with traffic flows on a network, between the firewall and the end users, and they actively deny attacks in realtime over the wire.**
* What shortcuts do you use on a regular basis? 
  - **[...]**
* What is the Linux Standard Base?
  - **The Linux Standard Base (LSB) is a joint project by several Linux distributions under the organizational structure of the Linux Foundation to standardize the software system structure, including the filesystem hierarchy used in the Linux operating system. The LSB is based on the POSIX specification, the Single UNIX Specification (SUS), and several other open standards, but extends them in certain areas.**
* What is an atomic operation?
  - **An atomic operation is an operation that is indivisible and irreducible (like an atom). When run, it is binary in nature in such that it either occurs or does not occur.**
* Your freshly configured http server is not running after a restart, what can you do?
  - **Check the `httpd.conf` for syntax errors, and check the logs in `/var/log/apache2/access.log` for clues.**
* What kind of keys are in ~/.ssh/authorized_keys and what it is this file used for?
  -**This file contains public keys from approved users, so they may login without a password.**
* I've added my public ssh key into authorized_keys but I'm still getting a password prompt, what can be wrong?
  - **You might have to edit `/etc/ssh/sshd_config` and make sure the following settings are set:**
  ```
  ChallengeResponseAuthentication no  
  PasswordAuthentication no  
  UsePAM no  
  ```
  - **You may have to restart the SSH daemon afterward, with `sshd restart`**
* Did you ever create RPM's, DEB's or solaris pkg's?
  - **Not I.**
* What does ```:(){ :|:& };:``` do on your system?
  - **It is a fork bomb. This one creates a function named `:`, which runs itself and pipes it through itself (forking forever), while running the whole fork process in the background.**
* How do you catch a Linux signal on a script?
  - **In Bash, one can use `trap`.**
* Can you catch a SIGKILL?
  - **No. SIGKILL (9), SIGSTOP (17), SIGCONT (19) cannot be caught and always uses the default action.**
* What's happening when the Linux kernel is starting the OOM killer and how does it choose which process to kill first?
  - **The kernel maintains an `oom_score`, which is maintained in the `/proc` filesystem (`procfs`). As a process' `oom_score` goes higher, it has a higher probability of getting killed.**
* Describe the linux boot process with as much detail as possible, starting from when the system is powered on and ending when you get a prompt.
  - **Basic Input Output System (BIOS) startup, which initializes hardware and devices, boot order, reads master boot record, etc.**
  - **GRUB (stands for GRand Unified Bootloader) loads the selected kernel into RAM and executes it. GRUB also loads other necessary resources.**
  - **`/sbin/init` - This program is the parent process of every program running on the system. This process always has a PID of `1` and is responsible for starting the rest of the processes that compose a Linux system.**
  - **`/etc/inittab` - Figures out which runlevel to enter and acts correspondingly**
  - **Essential functionality now online, auxiliary and secondary processes can load (GUI, etc)**
* What's a chroot jail?
  - **A `chroot` 'jail' is a way to isolate a user or process and its children from the rest of the system. `chroot` sets a directory to masquerade as the root of the filesystem.**
* When trying to umount a directory it says it's busy, how to find out which PID holds the directory?
  - **`fuser -c <directory/volume>` or `lsof | grep <directory/volume>`**
* What's LD_PRELOAD and when it's used?
  - **`LD_PRELOAD` is an optional environmental variable for the dynamic linker, which supplies libraries or objects that get preloaded before anything else. It can be used to include libraries in nonstandard locations or to override another library, useful when debugging. Because of this priority, it can be used maliciously.**
* You ran a binary and nothing happened. How would you debug this?
  - **Perhaps `strace` or `gdb`**
* What are cgroups? Can you specify a scenario where you could use them?
  - **`cgroups` are known as 'control groups', which is a kernel feature that limits, accounts for, and isolates the resource usage (CPU, memory, disk I/O, network, etc.) of a collection of processes.**
  - **`cgroups` are used to implement hierarchy and organization amongst processes and resources. They are prominent in orchestration and virtualization tools such as Docker and LXC.**


#### [⬆](#toc) <a name='expert'>Expert Linux Questions:</a>

* A running process gets ```EAGAIN: Resource temporarily unavailable``` on reading a socket. How can you close this bad socket/file descriptor without killing the process?
  - **`netstat` or `lsof | grep <process_name>` to find the process ID (PID) and file descriptor (FD). Then, `gdb -p <PID>` will attach the PID and you can close the socket with `call close(<FD>)` then `quit` to exit.**

#### [⬆](#toc) <a name='network'>Networking Questions:</a>

* What is localhost and why would ```ping localhost``` fail?
  - **Localhost refers to the computer you are on. `ping localhost` may fail if `/etc/hosts` does not have a `127.0.0.1 localhost` record, or if `/etc/nsswitch.conf` permissions are not set to `644` and `/etc/nsswitch.conf` does not have an entry like `hosts:   files dns`, or if the local loopback interface is not running (verify with `ifconfig`)**
* What is the similarity between "ping" & "traceroute" ? How is traceroute able to find the hops.
  - **`ping` sends a packet to an address and waits for a reply, measuring the time. `traceroute` traces a packet from your computer to an address, but it will also show you how many hops the packet requires to reach the host and how long each hop takes. `traceroute` works by sending packets with low time-to-live (TTL) values. The TTL value specifies how many hops the packet is allowed before it is returned. When a packet can't reach its destination because the TTL value is too low, the last host returns the packet and identifies itself. By sending a series of packets and incrementing the TTL value with each successive packet, `traceroute` finds out who all the intermediary hosts are.**
* What is the command used to show all open ports and/or socket connections on a machine?
  - **`netstat` or `lsof`**
* Is 300.168.0.123 a valid IPv4 address?
  - **No, because each tuple in the IPv4 4-byte tuple format can only be from 0-255 (`FF` in hex, 1 byte).**
* Which IP ranges/subnets are "private" or "non-routable" (RFC 1918)?
  - **The private or non-routable address segments are:**
    - **`10.0.0.0 - 10.255.255.255` (10/8 prefix)**
    - **`172.16.0.0 - 172.31.255.255` (172.16/12 prefix)**
    - **`192.168.0.0 - 192.168.255.255` (192.168/16 prefix)**
* What is a VLAN?
  - **Virtual Local Area Network (VLAN) is any broadcast domain that is partitioned and isolated in a network at the data link layer (OSI layer 2).**
  - **The purpose of a VLAN is simple: It removes the limitation of physical LANs, with all devices automatically connected to each other. With a VLAN, it is possible to have hosts that are connected together on the same physical LAN but not allowed to communicate directly. This restriction gives us the ability to organize a network without requiring that the physical LAN mirror the desired topology.**
* What is ARP and what is it used for?
  - **Address Resolution Protocol (ARP) is used by IPv4, to map IP addresses to the hardware addresses used by a data link protocol. ARP operates below the network layer, as part of the interface between the OSI network and OSI data link layer.**
* What is the difference between TCP and UDP?
  - **Transmission Control Protocol (TCP) is connection oriented— once a connection is established, data can be sent bidirectionally. Data packets are arranged in order, and has a delivery guarantee. TCP is slower than UDP, and has a larger header.**
  - **User/Universal Datagram Protocol (UDP) is a connectionless/stateless protocol, which sends multiple messages as packets in chunks, with no inherent order nor delivery guarantee.**
* What is the purpose of a default gateway?
  - **A default gateway acts as an intermediary device that connects devices on the local subnet to other devices, and also connects that to the Internet, bridging LAN and WAN. It enables devices to move packets from the subnet to the internet, as well as security features and other functionality.**
* What is command used to show the routing table on a Linux box?
  - **`netstat -r` or `sudo route`**
* A TCP connection on a network can be uniquely defined by 4 things. What are those things?
  - **Remote IP address, remote port, source IP address, and source port; these group together as a 4-tuple.**
* When a client running a web browser connects to a web server, what is the source port and what is the destination port of the connection?
  - **The source port is chosen randomly (between `1024` and `65536`), and the destination port of the web server is `80`.**
* How do you add an IPv6 address to a specific interface?
  - **`ifconfig <interface> inet6 add <ipv6address>/<prefixlength>`**
  - **`ip -6 addr add <ipv6address>/<prefixlength> dev <interface>`**
* You have added an IPv4 and IPv6 address to interface eth0. A ping to the v4 address is working but a ping to the v6 address gives yout the response ```sendmsg: operation not permitted```. What could be wrong?
  - **It is unable to send ICMP packets. Check if IPv6 is enabled; it may be blocked by default. In `ip6tables`, one could try:
    ```
    ip6tables -P INPUT ACCEPT
    ip6tables -P OUTPUT ACCEPT 
    ip6tables -P FORWARD ACCEPT
    ```**
* What is SNAT and when should it be used?
  - **Source/Secure Network Address Translation (SNAT) is commonly used to enable hosts with private addresses (RFC 1918) to connect to the public internet, regardless of their actual IP.**
* Explain how could you ssh login into a Linux system that DROPs all new incoming packets using a SSH tunnel.
  - **I think it would require access to the Linux system, from which you could enable remote port forwarding on an already-established outbound connection and port (i.e. `:80`), and then login via that SSH tunnel. Perhaps `sudo ssh <remote_username>@<remote_hostname> -p 80 -R 2222:localhost:22`, leave it running, and then login from outside with `ssh -p 2222 localhost`**
* How do you stop a DDoS attack?
  - **Traffic mitigation tactics, such as implementing globally-distributed web/DNS proxies (known as CDNs), network filters (block invalid packets, non-SYN packets, bogus TCP flags, spoofed packets from private subnet ranges), implementing rate limits and Geo-IP filters, `fail2ban` and `iptables`, etc.**
* How can you see content of an ip packet?
  - **`tcpdump`, `libpcap`, `tshark` (Wireshark), etc.**
* What is IPoAC (RFC 1149)?
  - **An April Fools' joke (1990) known as 'IP over Avian Carriers' (IPoAC). It proposed communicating internet traffic via homing pigeons.**


#### [⬆](#toc) <a name='mysql'>MySQL questions:</a>

* How do you create a user?
  - **`CREATE USER '<username>'@'<hostname>' IDENTIFIED BY '<password>';`**
* How do you provide privileges to a user?
  - **`GRANT <privilege> ON <database> . <table> TO '<username>'@'<hostname>';`**
* What is the difference between a "left" and a "right" join?
  - **The difference is in the way the tables are joined if there are no common records.**
    - **A `LEFT JOIN`, also known as `LEFT OUTER JOIN`, shows all records from the left table, and only matching records from the right table.**
    - **A `RIGHT JOIN`, also known as a `RIGHT OUTER JOIN` would be the opposite, keeping all fields of the right table, and only matching records from the left table.**
* Explain briefly the differences between InnoDB and MyISAM.
  - **Referential Integrity: InnoDB is a relational DBMS (RDBMS) and has referential integrity, ensuring relationships between tables remains consistent. MyISAM does not have this.**
  - **Transactions and Atomicity: Data in InnoDB is managed using Data Manipulation Language (DML) statements, such as `SELECT`, `INSERT`, `UPDATE` and `DELETE`, which is carried out atomically. MyISAM does not use or support atomic transactions. InnoDB can also undo or rollback operations; MyISAM cannot.**
  - **Concurrency: InnoDB tables are locked by row when queried, allowing concurrent operations, whereas MyISAM locks the entire table.**
  - **Reliability: InnoDB uses a transactional log, a double-write buffer and automatic checksumming and validation to prevent corruption. MyISAM offers no data integrity.**
  - **Essentially, one should never use MyISAM anymore unless forced to.**
* Describe briefly the steps you need to follow in order to create a simple master/slave cluster.
  - **Create two config files, `master.cnf` and `slave.cnf`, and give them separate `server-id` values. `server-id=1` for master, and `server-id=2` for slave.**
  - **Create the replication user. Then grant it `REPLICATION SLAVE` permissions. Example: `CREATE USER <replication_username>@<hostname>; GRANT REPLICATION SLAVE ON *.* TO <replication_username>@<hostname> IDENTIFIED BY '<password>';`**
  - **Initialize replication with:**
  ```
    CHANGE MASTER TO MASTER_HOST='<hostname>',
    -> MASTER_USER='<replication_username>',
    -> MASTER_PASSWORD='<password>',
    -> MASTER_PORT=3306;
  ```
  - **Start replication on the slave with: `start slave`**
* Why should you run `mysql_secure_installation` after installing MySQL?
  - **`mysql_secure_installation` greatly improves security defaults, by enabling the following:
    - **Allows one to set a password for root accounts.**
    - **Allows one to remove root accounts that are externally accessible.**
    - **Allows one to remove anonymous user accounts.**
    - **Allows one to remove the test database (which by default can be accessed by all users, even anonymous users), and also privileges that permit anyone to access databases with names that start with `test_`.**
* How do you check which jobs are running?
  - **`SHOW FULL PROCESSLIST;`**

#### [⬆](#toc) <a name='devop'>DevOps Questions:</a>

* Can you describe your workflow when you create a script?
  - **Analyze task requirements.**
  - **Google it.**
  - **(Chances are, it's already been done before and already exists on GitHub or StackOverflow. If not, then break it down into smaller parts and google those parts instead.)**
* What is GIT?
  - **Git is a distributed version control system (VCS), and a source code management (SCM) system.**
* What is a dynamically/statically linked file?
  - **A statically-linked file would copy all dependencies and external library modules used in the program into the final executable. In dynamic linking, only the names of the dependencies and external library modules are placed in the final executable, while the actual linking takes place at runtime when both executable file and libraries are placed in the memory. In dynamic linking, only one copy of shared library is kept in memory, whereas in static linking, the libraries are baked-in.**
* What does "./configure && make && make install" do?
  - **`./configure ` runs the configure script, which likely ensures dependencies and whatnot. `make` builds the software, according to the Makefile. `make install` will copy the built program, and its libraries and documentation, to the correct final locations.**
* What is Puppet/Chef/Ansible used for?
  - **Configuration management, infrastructure automation and orchestration, at scale.**
* What is Nagios/Zenoss/NewRelic used for?
  - **System monitoring for networks, hardware, infrastructure and resources, often security-related.**
* What is the difference between Containers and VMs?
  - **Virtual machines (VMs) have a full OS with all of its associated resource overhead. Hypervisors allow multiple instances of OSs to be run in parallel. Each VM/OS runs as a discrete individual entity from the host system.**
  - **Containers are self-contained environments that share the kernel of the host OS, along with other resources. They are more streamlined, lightweight, and purpose-built than VMs.**
  - **VMs are like houses, containers are like apartment units within an apartment building.**
* How do you create a new postgres user?
  - **In PostgreSQL: `"CREATE USER <username> WITH PASSWORD '<password>';"`**
* What is a virtual IP address? What is a cluster?
  - **Virtual IP addresses (VIP or VIPA) are IP addresses that do not correspond to an actual physical network interface (port). Uses for VIP/VIPAs include NATS (especially one-to-many NATs), fault-tolerance (load-balancing, redundancy, pools), and mobility. Just like its physical counterpart, they are essentially IPs for virtual resources and servers.**
  - **A computer cluster consists of a set of loosely or tightly connected computers that work together so that, in many respects, they can be viewed as a single system.**
* How do you print all strings of printable characters present in a file?
  - **`strings <filename>`**
* How do you find shared library dependencies?
  - **`ldd -v <filename>`**
* What is Automake and Autoconf?
  - **`automake` is an automation tool for the compilation process.  It takes care of automatically generating the dependency information in an effort to dynamically link libraries. It can also automatically generate makefiles.**
  - **`autoconf` is a convenience tool for producing `configure` scripts for building, installing and packaging software on a target system or OS.**
* ./configure shows an error that libfoobar is missing on your system, how could you fix this, what could be wrong?
  - **Install the `libfoobar` package or build it from source. If `libfoobar` is already installed, its path may need to be added to `/etc/ld.so.conf`**
* What are the advantages/disadvantages of script vs compiled program?
  - **Scripts are instructions written in language that are interpreted by another program. They are portable and flexible, and can be run directly, however, their source code is visible and are slower than compiled programs.**
  - **Compiled programs are faster and optimized due to directly using the native code of the target platform/processor (and thus obscure the source code). However, they have a lengthier development process (editing, compiling, linking, executing) and require a different executable compiled for each target platform/processor.**
* What's the relationship between continuous delivery and DevOps?
  - **DevOps aims to facilitate the process of provisioning infrastructure and environments and applications, combining 'development' with 'operations'. It is compatible with, supports and encompasses continuous delivery.**
* What are the important aspects of a system of continuous integration and deployment?
  - **Rampant automation in everything, granular unit tests, frequent integration tests, automated builds, code quality control, highly accessible by all, agile.**
#### [⬆](#toc) <a name='fun'>Fun Questions:</a>

* A careless sysadmin executes the following command: ```chmod 444 /bin/chmod ``` - what do you do to fix this?
  - **Perl: `perl -e 'chmod 0755, "/bin/chmod"'`**
  - **Python3: `python -c 'import os;os.chmod("/bin/chmod", 0o755)'`**
  - **Ruby: `ruby -r fileutils -e 'FileUtils.chmod 0755, "/bin/chmod"'`**
  - **GNU install:**
  ```
    sudo install -m 0755 /bin/chmod /bin/chmod.fix  
    sudo mv /bin/chmod /bin/chmod.bad  
    sudo mv /bin/chmod.fix /bin/chmod  
  ```
* I've lost my root password, what can I do?
  - **Ubuntu-style instructions: Reboot into the GRUB menu at startup, by pressing `Shift` at BIOS.**
  - **Select your normal boot option and press `e` to edit.**
  - **Locate the line starting with `linux` or `kernel` and replace `ro` with `rw init=/bin/bash` (press `e` to edit)**
  - **Press `Enter` then `b` to boot with the new settings.**
  - **Use `passwd root <new_password>`, or edit the record information in `sudo vipw` or `sudo vipw -s`**
* I've rebooted a remote server but after 10 minutes I'm still not able to ssh into it, what can be wrong?
  - **Maybe it is an error within `/etc/ssh/sshd_config`, or it is a firewall or `iptables` error, or `/etc/ssh/sshd_config` is somehow configured to listen on another port.**
* If you were stuck on a desert island with only 5 command-line utilities, which would you choose?
  - **Anything that would help me communicate with the outside world and escape the island: `lynx`, `mail`, `netcat`, `nmap`, `ftp`**
* You come across a random computer and it appears to be a command console for the universe. What is the first thing you type?
  - **`whoami`**
* Tell me about a creative way that you've used SSH?
  - **[...]**
* You have deleted by error a running script, what could you do to restore it?
  - **`lsof | grep <deleted_file>` to find the PID currently running it, and the file descriptod (FD).**
  - **`cp /proc/<PID>/fd/<FD> <new_file>` to copy the contents to a new file**
* What will happen on 19 January 2038?
  - **The Year 2038 Problem. It specifically affects software using a signed 32-bit integer system. This 32-bit integer is interpreted as the number of seconds since `00:00:00 UTC 1 January 1970` (the Unix epoch), and will overflow on `03:14:07 UTC 19 January 2038`, finally reaching the maximum value of 2147483647.**

#### [⬆](#toc) <a name='demo'>Demo Time:</a>

* Unpack test.tar.gz without man pages or google.
  - **`tar -xzf test.tar.gz`**
* Remove all "*.pyc" files from testdir recursively?
  - **`find testdir/ -name "*.pyc" -type f -delete`**
* Search for "my konfu is the best" in all *.py files.
  - **`grep "my konfu is the best" -r --include="*.py" ~`**
* Replace the occurrence of "my konfu is the best" with "I'm a linux jedi master" in all *.txt files.
  - **`find ./testdir -type f -name "*.txt" | xargs sed -i "s/my konfu is the best/I\'m a linux jedi master/"`**
* Test if port 443 on a machine with IP address X.X.X.X is reachable.
  - **Telnet: `telnet X.X.X.X 443`**
  - **Netcat: `nc -z -v X.X.X.X 443`**
  - **Nmap: `nmap X.X.X.X | grep 443`**
* Get http://myinternal.webserver.local/test.html via telnet.
  - **`telnet http://myinternal.webserver.local 80`**
  - **`GET /test.html HTTP/1.1`**
  - **`HOST: myinternal.webserver.local`**
  - **`<ENTER>`**
  - **`<ENTER>`**
* How to send an email without a mail client, just on the command line?
  - **Enter `mail -s "Hello World" someone@example.com`, then input the message in the terminal and then hit <Ctrl+D> to exit the prompt and send the message.**
* Write a ```get_prim``` method in python/perl/bash/pseudo.
  - **python:**
  ```
  def get_prim(n):
      return not any(n%i == 0 for i in range(2, n))
  ```
* Find all files which have been accessed within the last 30 days.
  - **`find . -type f -atime -30`**
* Explain the following command ```(date ; ps -ef | awk '{print $1}' | sort | uniq | wc -l ) >> Activity.log```
  - **It prints the date, then takes the process list of all running processes, and their attributes, then cuts out the first column, sorts it alphanumerically, finds the unique listings, and counts the total remaining lines, which it appends into `Activity.log`**
* Write a script to list all the differences between two directories.
  - **`diff -r dir1 dir2`**
* In a log file with contents as ```<TIME> : [MESSAGE] : [ERROR_NO] - Human readable text``` display summary/count of specific error numbers that occurred every hour or a specific hour.
  - **`cat log | awk -F ":" '{print $3}'|sort -n |uniq -c`**

#### [⬆](#toc) <a name='references'>Other Great References:</a>

Some questions are 'borrowed' from other great references like:

* https://github.com/darcyclarke/Front-end-Developer-Interview-Questions
* https://github.com/kylejohnson/linux-sysadmin-interview-questions/blob/master/test.md
* http://slideshare.net/kavyasri790693/linux-admin-interview-questions
