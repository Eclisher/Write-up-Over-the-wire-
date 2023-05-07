  ## Over The Wire
  # Write by Harizo
  ## _Bandit_

### Bandit Level 0
Level Goal

The goal of this level is for you to log into the game using SSH. The host to which you need to connect is bandit.labs.overthewire.org, on port 2220. The username is bandit0 and the password is bandit0. Once logged in, go to the Level 1 page to find out how to beat Level 1.
Commands you may need to solve this level

ssh
Helpful Reading Material

    Secure Shell (SSH) on Wikipedia
    How to use SSH on wikiHow


  - # Level 0 
  ```sh
  bandit0@bandit:~$ ls
  readme
  bandit0@bandit:~$ cat readme
  ```


##  Bandit Level 1 → Level 2
Level Goal

The password for the next level is stored in a file called - located in the home directory
Commands you may need to solve this level

ls , cd , cat , file , du , find
Helpful Reading Material

    Google Search for “dashed filename”
    Advanced Bash-scripting Guide - Chapter 3 - Special Characters


  - # Level 1 --> Level 2
  ```sh
  bandit1@bandit:~$ cat ./-
  rRGizSaX8Mk1RTb1CNQoXTcYZWU6lgzi
  ```

## Bandit Level 2 → Level 3
Level Goal

The password for the next level is stored in a file called spaces in this filename located in the home directory
Commands you may need to solve this level

ls , cd , cat , file , du , find
Helpful Reading Material

    Google Search for “spaces in filename”


  - # Level 2 --> Level 3
  ```sh
  bandit2@bandit:~$ ls
  spaces in the filename
  bandit2@bandit:~$ cat ./spaces\ in\ this\ filename
  aBZ0W5EmUfAf7kHTQeOwd8bauFJ2lAiG
  ```

## Bandit Level 3 → Level 4
Level Goal

The password for the next level is stored in a hidden file in the inhere directory.
Commands you may need to solve this level

ls , cd , cat , file , du , find

  - # Level 3 --> Level 4
  ```sh
  bandit3@bandit:~$ ls 
  inhere
  bandit3@bandit:~$ cd inhere/
  bandit3@bandit:~/inhere$ ls -a
  . .. .hidden
  bandit3@bandit:~/inhere$ cat .hidden
  2EW7BBsr6aMMoJ2HjW067dm8EgX26xNe
  ```

## Bandit Level 4 → Level 5
Level Goal

The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.
Commands you may need to solve this level

ls , cd , cat , file , du , find

  - # Level 4 --> Level 5
  ```sh
  bandit4@bandit:~$ cd inhere/
  bandit4@bandit:~$ file ./file0*
  bandit4@bandit:~$ cat ./-file07
  lrIWWI6bB37kxfiCQZqUdOIYfr6eEeqR
  ```

## Bandit Level 5 → Level 6
Level Goal

The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:

    human-readable
    1033 bytes in size
    not executable

Commands you may need to solve this level

ls , cd , cat , file , du , find

  - # Level 5  --> Level 6
  ```sh
  bandit5@bandit:~$ ls
  bandit5@bandit:~$ cd maybehere07
  bandit5@bandit:~$ cat .file2
    P4L4vucdmLnm8I7Vl7jG1ApGSfjYKqJU
  ```

## Bandit Level 6 → Level 7
Level Goal

The password for the next level is stored somewhere on the server and has all of the following properties:

    owned by user bandit7
    owned by group bandit6
    33 bytes in size

Commands you may need to solve this level

ls , cd , cat , file , du , find , grep

  - # Level 6  --> Level 7
  ```sh
  bandit6@bandit:~$ find / -user bandit7 -group 
  bandit6 -size 33c 2>&1 | grep -F -v Permission | grep -F -v directory
  bandit6@bandit:~$  cat /var/lib/dpkg/info/bandit7.password
  z7WtoNQU2XfjmMtWA8u5rN4vzqu4v99S
  ```

## Bandit Level 7 → Level 8
Level Goal

The password for the next level is stored in the file data.txt next to the word millionth
Commands you may need to solve this level

man, grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd



  - # Level 7  --> Level 8

  ```sh
  bandit7@bandit:~$  ls
  bandit7@bandit:~$  cat data.txt | grep millionth
  millionth	TESKZC0XvTetK0S9xNwm25STk5iWrBvP

  ```
## Bandit Level 8 → Level 9
Level Goal

The password for the next level is stored in the file data.txt and is the only line of text that occurs only once
Commands you may need to solve this level

grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd

  - # Level  8 --> Level 9
  ```sh
  bandit8@bandit:~$ cat data.txt | sort | uniq -c -u
  N632PlfYiZbn3PhVK3XOGSlNInNE00t
  ```

## Bandit Level 9 → Level 10
Level Goal

The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.
Commands you may need to solve this level

grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd

  - # Level  9 --> Level 10
  ```sh
  bandit9@bandit:~$ strings data.txt
  G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s

  ```
## Bandit Level 10 → Level 11
Level Goal

The password for the next level is stored in the file data.txt, which contains base64 encoded data
Commands you may need to solve this level

grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd
  - # Level  10 --> Level 11
  ```sh
  bandit10@bandit:~$ cat data.txt | base64 -d
  The password is 6zPeziLdR2RKNdNYFNb6nVCKzphlXHBM


  ```
## Bandit Level 11 → Level 12
Level Goal

The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions
Commands you may need to solve this level

grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd
  - # Level  11 --> Level 12
  ```sh
  bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
  The password is JVNBBFSmZwKKOP0XbFXOoW8chDz5yVRv

  ```
## Bandit Level 12 → Level 13
Level Goal

The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv (read the manpages!)
Commands you may need to solve this level

grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd, mkdir, cp, mv, file
  - # Level  12 --> Level 13
  ```sh

  bandit12@bandit:~$ mkdir /tmp/random_dir
  bandit12@bandit:~$ cd /tmp/random_dir
  bandit12@bandit:/tmp/random_dir$
  bandit12@bandit:/tmp/random_dir$ cp ~/data.txt .
  bandit12@bandit:/tmp/random_dir$ ls
  bandit12@bandit:/tmp/random_dir$ mv data.txt data
  bandit12@bandit:/tmp/random_dir$ ls
  bandit12@bandit:/tmp/random_dir$ xxd -r data > binary
  bandit12@bandit:/tmp/random_dir$ file binary
  bandit12@bandit:/tmp/random_dir$ mv binary binary.gz
  bandit12@bandit:/tmp/random_dir$  gunzip binary.gz
  bandit12@bandit:/tmp/random_dir$ file binary
  bandit12@bandit:/tmp/random_dir$ bunzip2 binary
  bandit12@bandit:/tmp/random_dir$ file binary.out
  bandit12@bandit:/tmp/random_dir$ mv binary.out binary.gz
  bandit12@bandit:/tmp/random_dir$ gunzip binary.gz
  The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL


  ```
## Bandit Level 13 → Level 14
Level Goal

The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on
Commands you may need to solve this level

ssh, telnet, nc, openssl, s_client, nmap
  - # Level  13 --> Level 14
  ```sh
  bandit13@bandit:~$ ls
  sshkey.private
  bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost
  ```
  When this command is failed,
  you must enter a command: 

  ```sh
  bandit13@bandit:~$ exit
  harizo@harizo-TECRA-A50-C:~$ ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
  ```
## Bandit Level 14 → Level 15
Level Goal

The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.
Commands you may need to solve this level

ssh, telnet, nc, openssl, s_client, nmap
  - # Level  14 --> Level 15
  ```sh
  bandit15@bandit:~$ cat /etc/bandit_pass/bandit15

  bandit15@bandit:~$ openssl s_client -connect localhost:30001
  jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt
  Correct!
  JQttfApK4SeyHwDlI9SXGR50qclOAil1

  ```
## Bandit Level 15 → Level 16
Level Goal

The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption.

Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…
Commands you may need to solve this level

ssh, telnet, nc, openssl, s_client, nmap
  - # Level  15 --> Level 16
  ```sh
  bandit16@bandit:~$ cat /etc/bandit_pass/bandit16
  JQttfApK4SeyHwDlI9SXGR50qclOAil1
  bandit16@bandit:~$ openssl s_client --connect localhost:31790
  read R BLOCK
  JQttfApK4SeyHwDlI9SXGR50qclOAil1
  bandit16@bandit:~$ mkdir /tmp/random_sshkeybandit16@bandit:~$ cd /tmp/random_sshkeybandit16@bandit:/tmp/random_sshkey$ touch private.key

  bandit16@bandit:/tmp/random_sshkey$ vim private.key
  bandit16@bandit:/tmp/random_sshkey$ cd #
  bandit16@bandit:~$ exit
  harizo@harizo-TECRA-A50-C:~$ ssh -i sshkey.private bandit17@bandit.labs.overthewire.org -p 2220
  VwOSWtCA7lRKkTfbr2IDh6awj9RNZM5e

  ```
## Bandit Level 16 → Level 17
Level Goal

The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.
Commands you may need to solve this level

ssh, telnet, nc, openssl, s_client, nmap
  - # Level  16 --> Level 17
  ```sh
  bandit17@bandit:~$ diff passwords.old passwords.new
  42c42
  < glZreTEH1V3cGKL6g4conYqZqaEj0mte
  ---
  > hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg

  ```

## Bandit Level 17 → Level 18
Level Goal

There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new

NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19
Commands you may need to solve this level

cat, grep, ls, diff

  - # Level  17 --> Level 18
  ```sh
  harizo@harizo-TECRA-A50-C:~$ ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
  ```
                          _                     _ _ _   
                          | |__   __ _ _ __   __| (_) |_ 
                          | '_ \ / _` | '_ \ / _` | | __|
                          | |_) | (_| | | | | (_| | | |_ 
                          |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                        

                        This is an OverTheWire game server. 
              More information on http://www.overthewire.org/wargames

  bandit18@bandit.labs.overthewire.org's password: 

  awhqfNnAbc1naukrpqDYcF95h7HoMTrC


## Bandit Level 18 → Level 19
Level Goal

The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.
Commands you may need to solve this level

ssh, ls, cat


  - # Level  18 --> Level 19

                          _                     _ _ _   
                          | |__   __ _ _ __   __| (_) |_ 
                          | '_ \ / _` | '_ \ / _` | | __|
                          | |_) | (_| | | | | (_| | | |_ 
                          |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                        

                        This is an OverTheWire game server. 
              More information on http://www.overthewire.org/wargames

  bandit18@bandit.labs.overthewire.org's password:awhqfNnAbc1naukrpqDYcF95h7HoMTrC 


## Bandit Level 19 → Level 20
Level Goal

To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

  - # Level  19 --> Level 20
  ```sh
  bandit19@bandit:~$ ls
  bandit20-do
  bandit19@bandit:~$ file bandit20-do
  bandit20-do: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=c148b21f7eb7e816998f07490c8007567e51953f, for GNU/Linux 3.2.0, not stripped
  bandit19@bandit:~$ ./bandit20-do
  Run a command as another user.
    Example: ./bandit20-do id
  bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
  VxCazJaVykI6W36BkBU0mJTCM8rR95XT

  ```




## Bandit Level 20 → Level 21
Level Goal

There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

NOTE: Try connecting to your own network daemon to see if it works as you think
Commands you may need to solve this level

ssh, nc, cat, bash, screen, tmux, Unix ‘job control’ (bg, fg, jobs, &, CTRL-Z, …)

  - # Level 20  --> Level 21
  ```sh
  bandit20@bandit:~$ echo -n 'VxCazJaVykI6W36BkBU0mJTCM8rR95XT' | nc -l -p 1234 &
  [1] 2227708
  bandit20@bandit:~$ ./suconnect 1234
  Read: VxCazJaVykI6W36BkBU0mJTCM8rR95XT
  Password matches, sending next password
  NvEJF7oVjkddltPSrdKEFOllh9V1IBcq
  [1]+  Done                    
  echo -n 'VxCazJaVykI6W36BkBU0mJTCM8rR95XT' | nc -l -p 1234
  ```

## Bandit Level 21 → Level 22
Level Goal

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.
Commands you may need to solve this level

cron, crontab, crontab(5) (use “man 5 crontab” to access this)

  - # Level  21  --> Level 22
  ```sh
  bandit21@bandit:~$ ls -la /etc/cron.d
  total 56
  drwxr-xr-x   2 root root  4096 Apr 23 18:05 .
  drwxr-xr-x 108 root root 12288 Apr 23 18:05 ..
  -rw-r--r--   1 root root    62 Apr 23 18:04 cronjob_bandit15_root
  -rw-r--r--   1 root root    62 Apr 23 18:04 cronjob_bandit17_root
  -rw-r--r--   1 root root   120 Apr 23 18:04 cronjob_bandit22
  -rw-r--r--   1 root root   122 Apr 23 18:04 cronjob_bandit23
  -rw-r--r--   1 root root   120 Apr 23 18:04 cronjob_bandit24
  -rw-r--r--   1 root root    62 Apr 23 18:04 cronjob_bandit25_root
  -rw-r--r--   1 root root   201 Jan  8  2022 e2scrub_all
  -rwx------   1 root root    52 Apr 23 18:05 otw-tmp-dir
  -rw-r--r--   1 root root   102 Mar 23  2022 .placeholder
  -rw-r--r--   1 root root   396 Feb  2  2021 sysstat
  bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
  @reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
  * * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
  bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
  #!/bin/bash
  chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
  cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
  bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

  WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff


  ```

## Bandit Level 22 → Level 23
Level Goal

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.
Commands you may need to solve this level

cron, crontab, crontab(5) (use “man 5 crontab” to access this)

  - # Level  22  --> Level 23
  ```sh
  bandit22@bandit:~$ ls -la /etc/cron.d
  total 56
  drwxr-xr-x   2 root root  4096 Apr 23 18:05 .
  drwxr-xr-x 108 root root 12288 Apr 23 18:05 ..
  -rw-r--r--   1 root root    62 Apr 23 18:04 cronjob_bandit15_root
  -rw-r--r--   1 root root    62 Apr 23 18:04 cronjob_bandit17_root
  -rw-r--r--   1 root root   120 Apr 23 18:04 cronjob_bandit22
  -rw-r--r--   1 root root   122 Apr 23 18:04 cronjob_bandit23
  -rw-r--r--   1 root root   120 Apr 23 18:04 cronjob_bandit24
  -rw-r--r--   1 root root    62 Apr 23 18:04 cronjob_bandit25_root
  -rw-r--r--   1 root root   201 Jan  8  2022 e2scrub_all
  -rwx------   1 root root    52 Apr 23 18:05 otw-tmp-dir
  -rw-r--r--   1 root root   102 Mar 23  2022 .placeholder
  -rw-r--r--   1 root root   396 Feb  2  2021 sysstat
  bandit22@bandit:~$ cat /etc/cron.d/cronjob_bandit23
  @reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
  * * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
  bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
  #!/bin/bash

  myname=$(whoami)
  mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

  echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

  cat /etc/bandit_pass/$myname > /tmp/$mytarget
  bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
  8ca319486bfbbc3663ea0fbe81326349
  8ca319486bfbbc3663ea0fbe81326349
  8ca319486bfbbc3663ea0fbe81326349: command not found
  bandit22@bandit:~$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
  8ca319486bfbbc3663ea0fbe81326349
  bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
  QYw0Y2aiA672PsMmh9puTQuhoz8SyR2G

  ```


  ## License

  MIT

  **Free Software, Hell Yeah!**

  [//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job. There is no need to format nicely because it shouldn't be seen. Thanks SO - http://stackoverflow.com/questions/4823468/store-comments-in-markdown-syntax)

    [dill]: <https://github.com/joemccann/dillinger>
    [git-repo-url]: <https://github.com/joemccann/dillinger.git>
    [john gruber]: <http://daringfireball.net>
    [df1]: <http://daringfireball.net/projects/markdown/>
    [markdown-it]: <https://github.com/markdown-it/markdown-it>
    [Ace Editor]: <http://ace.ajax.org>
    [node.js]: <http://nodejs.org>
    [Twitter Bootstrap]: <http://twitter.github.com/bootstrap/>
    [jQuery]: <http://jquery.com>
    [@tjholowaychuk]: <http://twitter.com/tjholowaychuk>
    [express]: <http://expressjs.com>
    [AngularJS]: <http://angularjs.org>
    [Gulp]: <http://gulpjs.com>

    [PlDb]: <https://github.com/joemccann/dillinger/tree/master/plugins/dropbox/README.md>
    [PlGh]: <https://github.com/joemccann/dillinger/tree/master/plugins/github/README.md>
    [PlGd]: <https://github.com/joemccann/dillinger/tree/master/plugins/googledrive/README.md>
    [PlOd]: <https://github.com/joemccann/dillinger/tree/master/plugins/onedrive/README.md>
    [PlMe]: <https://github.com/joemccann/dillinger/tree/master/plugins/medium/README.md>
    [PlGa]: <https://github.com/RahulHP/dillinger/blob/master/plugins/googleanalytics/README.md>
