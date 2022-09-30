
# sudo ./dist/ctrace trace --event openat
sudo ./dist/ctrace trace --set net --set fs --exclude-comm bash


# sudo ./dist/ctrace trace --set clone --exclude-comm node sshd cpuUsage.sh
# sudo ./dist/ctrace trace --set fs  --exclude-comm node sshd cpuUsage cpptools cat
