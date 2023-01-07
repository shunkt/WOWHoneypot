echo 'installing WOWHoneypot in /opt/wowhoney'
target=/opt/wowhoney
mkdir -p $target
cp -r ./art $target/art
cp -r ./bin $target/bin
mkdir -p $target/log
cp chase-url.py $target/
cp mrr_checker.py $target/
cp wowhoneypot.py $target/
cp ./services/wowhoneypot.service /lib/systemd/system/
chmod 644 /lib/systemd/system/wowhoneypot.service

chmod 755 $target/bin/start.sh

echo 'fiinished'
