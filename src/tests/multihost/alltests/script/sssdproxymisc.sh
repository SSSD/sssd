expect -f  - <<<'
    spawn ssh -o StrictHostKeyChecking=no -l foo12 localhost
    expect "*assword:"
    send -- "Secret123\r"
    expect "*$ "
    send -- "passwd\r"
    expect "*Current Password: "
    send -- "Secret123\r"
    expect "New password: "
    send -- "LsaASion#@123\r"
    expect "Retype new password: "
    send -- "LsaASion#@123\r"
    expect "*"
    send -- "logout\r"
    expect eof
'
