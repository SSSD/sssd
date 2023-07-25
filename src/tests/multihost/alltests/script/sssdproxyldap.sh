expect -f - <<<'
    spawn ssh -o StrictHostKeyChecking=no -l foo2@example1 localhost
    expect "*password: "
    send "Secret123\r"
    expect "Current Password: "
    send "Secret123\r"
    expect "New password: "
    send "NewKrbPass_123\r"
    expect "Retype new password: "
    send "NewKrbPass_123\r"
    expect eof
'
