// resources/firejail/chromium.profile
# Firejail profile for Chromium-based browsers in RustVault
# Applies to Chrome, Chromium, Edge, Brave, etc.

# Secure by default
include /etc/firejail/default.profile

# Chromium-specific sandbox
include /etc/firejail/chromium-common.profile

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

# Allow access to common Chrome/Chromium files
# Add more paths if needed for your specific setup
noblacklist ${HOME}/.config/google-chrome
noblacklist ${HOME}/.config/chromium
noblacklist ${HOME}/.cache/google-chrome
noblacklist ${HOME}/.cache/chromium