Connecting to host via SSH
##########################

You can use :class:`pytest_mh.ssh.SSHClient` to connect to any host as any
user. It is not recommended to instantiate this class on yourself but you should
rather use :meth:`pytest_mh.MultihostRole.ssh` to get the client
object.

Once you establish SSH connections, you can run commands on the remote host in
both blocking and non-blocking mode.

.. code-block:: python
    :caption: Example calls

    @pytest.mark.topology(KnownTopology.Client)
    def test_ssh_client(client: Client):
        # Establish connection as user 'ci' with given password
        with client.ssh('ci', 'Secret123') as ssh:
            # Run command
            result = ssh.run('echo "Hello World"')
            assert result.stdout == 'Hello World'

            # Run multiline commands
            result = ssh.run('''
            echo "Hello"
            echo "World"
            ''')
            assert result.stdout_lines == ['Hello', 'World']

            # Provide custom environment
            result = ssh.run('echo $TEST', env={'TEST': 'Hello World'})
            assert result.stdout == 'Hello World'

            # Provide input
            result = ssh.run('cat', input='Hello World')
            assert result.stdout == 'Hello World'

            # Set working directory
            result = ssh.run('pwd', cwd='/')
            assert result.stdout == '/'

            # Run exec-style arguments
            result = ssh.exec(['echo', 'Hello World'])
            assert result.stdout == 'Hello World'

            # Run non-blocking commands
            process = ssh.async_run('echo "Non-blocking Hello World"')
            result = process.wait()
            assert result.stdout == 'Non-blocking Hello World'

            # Interact more, process.wait() is called automatically
            with ssh.async_run('bash') as process:
                process.stdin.write('echo Hello\n')
                assert next(process.stdout) == 'Hello'
                process.stdin.write('echo World\n')
                assert next(process.stdout) == 'World'
