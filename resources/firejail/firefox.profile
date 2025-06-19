// resources/firejail/firefox.profile
# Firejail profile for Firefox in RustVault
# Description: Safe and secure web browser

# Secure by default
include /etc/firejail/default.profile

# Firefox-specific sandbox
include /etc/firejail/firefox-common.profile

# Additional security for RustVault
caps.drop all
seccomp
nonewprivs
noroot

# Filesystem restrictions
private-dev
private-tmp
private-cache

# Networking restrictions
netfilter
protocol unix,inet,inet6

# Allow access to common Firefox files
# Add more paths if needed for your specific setup
noblacklist ${HOME}/.mozilla
noblacklist ${HOME}/.cache/mozilla