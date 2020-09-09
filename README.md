# sshoney

This is a simple honeypot for SSH.

It's essentially a wrapper around golang.org/x/crypto/ssh
that does some logging to stdout. There's definitely
potential for improvement.

I had a few goals with this:
  - reproduce results from [this blog post](https://systemoverlord.com/2020/09/04/lessons-learned-from-ssh-credential-honeypots.html)
  - poke about in the SSH RFCs and openssh/golang's implementation thereof
  - try out go.uber.org/zap and golang.org/x/crypto/ssh
