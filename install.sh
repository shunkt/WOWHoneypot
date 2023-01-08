echo 'installing WOWHoneypot in /opt/wowhoney'

if type "python3" > /dev/null 2>&1; then
    python=python3
elif type "python" > /dev/null 2>&1; then
    python=python
else
    echo 'python3 is not installed'
    exit 1
fi

$python -m pip install -r requirements.txt

target=/opt/wowhoney
mkdir -p $target
cp -r ./art $target
cp -r ./bin $target
mkdir -p $target/log
cp chase-url.py $target/
cp mrr_checker.py $target/
cp wowhoneypot.py $target/
cp config.txt $target/
cp ./services/wowhoneypot.service /lib/systemd/system/
chmod 644 /lib/systemd/system/wowhoneypot.service

chmod 755 $target/bin/start.sh

echo 'fiinished'
