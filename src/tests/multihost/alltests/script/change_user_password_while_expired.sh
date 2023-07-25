expect -f  - <<<'
    spawn ssh -o StrictHostKeyChecking=no -l ppuser1 localhost
    expect "*password: "
    send "Secret123\r"
    expect "*Current Password: "
    send "Secret123\r"
    expect "New password: "
    send "NewPass_123\r"
    expect "Retype new password: "
    send "NewPass_123\r"
    expect eof
'
