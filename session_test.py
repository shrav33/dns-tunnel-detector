import time
import datetime

print("Sending 30 queries to evil-c2.net...")
with open('shared/dns_log.txt', 'a') as f:
    for i in range(30):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        f.write(f'{ts}, word{i}.evil-c2.net\n')
        f.flush()
        print(f"Sent: word{i}.evil-c2.net")
        time.sleep(1)
print("Done! Session alert should have fired.")