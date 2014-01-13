list keys?
 execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--with-fingerprint", "--fixed-list-mode", "--with-colons", "--list-secret-keys"], [/* 9 vars */]) = 0
 
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--fixed-list-mode", "--with-colons", "--list-keys", "E7A4C6CFA84A7140", "00E5915AC416D5EA", "FC97D29FCA0557EF", "41A0A3C8ADDDD9E5"], [/* 9 vars */]) = 0

encrypt
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--comment", "Using GnuPG with Icedove - http://www.enigmail.net/", "-a", "-t", "--encrypt", "--always-trust", "--encrypt-to", "0xADDDD9E5", "-r", "<s@ctrlc.hu>", "-u", "0xADDDD9E5"], [/* 9 vars */]) = 0

decrypt
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--decrypt", "--passphrase-fd", "0", "--no-use-agent"], [/* 9 vars */]) = 0

verify
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--verify"], [/* 9 vars */]) = 0

get signers details
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--fixed-list-mode", "--with-colons", "--list-keys", "5337E3B760DEC17F"], [/* 9 vars */]) = 0

sign
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--comment", "Using GnuPG with Icedove - http://www.enigmail.net/", "-t", "--clearsign", "-u", "0xADDDD9E5", "--passphrase-fd", "0", "--no-use-agent"], [/* 9 vars */]) = 0

key properties
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--with-fingerprint", "--fixed-list-mode", "--with-colons", "--list-keys"], [/* 9 vars */]) = 0

execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--with-fingerprint", "--fixed-list-mode", "--with-colons", "--list-secret-keys"], [/* 9 vars */]) = 0

execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--batch", "--no-tty", "--status-fd", "2", "--with-fingerprint", "--fixed-list-mode", "--with-colons", "--list-sig", "0x5337E3B760DEC17F"], [/* 9 vars */]) = 0

sign key
execve("/usr/bin/gpg", ["/usr/bin/gpg", "--charset", "utf-8", "--display-charset", "utf-8", "--passphrase-fd", "0", "--no-use-agent", "--no-tty", "--status-fd", "1", "--logger-fd", "1", "--command-fd", "0", "-u", "0xFC97D29FCA0557EF", "--ask-cert-level", "--edit-key", "5337E3B760DEC17F", "lsign"], [/* 9 vars */]) = 0


 /usr/bin/gpg --fixed-list-mode --with-colons --list-keys E7A4C6CFA84A7140 00E5915AC416D5EA FC97D29FCA0557EF 41A0A3C8ADDDD9E5
 /usr/bin/gpg --fixed-list-mode --with-colons --list-keys 5337E3B760DEC17F
 /usr/bin/gpg -a -t --encrypt --always-trust --encrypt-to 0xADDDD9E5 -r <s@ctrlc.hu> -u 0xADDDD9E5
 /usr/bin/gpg --decrypt --passphrase-fd 0 --no-use-agent
 /usr/bin/gpg --verify
 /usr/bin/gpg -t --clearsign -u 0xADDDD9E5 --passphrase-fd 0
 /usr/bin/gpg --with-fingerprint --fixed-list-mode --with-colons --list-keys
 /usr/bin/gpg --with-fingerprint --fixed-list-mode --with-colons --list-secret-keys
 /usr/bin/gpg --with-fingerprint --fixed-list-mode --with-colons --list-sig 0x5337E3B760DEC17F
 /usr/bin/gpg --passphrase-fd 0 --status-fd 1 --logger-fd 1 --command-fd 0 -u 0xFC97D29FCA0557EF --ask-cert-level --edit-key 5337E3B760DEC17F lsign
