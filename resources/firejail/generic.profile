// resources/firejail/generic.profile
# Firejail profile for generic browsers in RustVault

# Secure by default
include /etc/firejail/default.profile

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

# Reasonable set of browser-related directories
# Modify as needed for specific browsers
noblacklist ${HOME}/.config
noblacklist ${HOME}/.cache