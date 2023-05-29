

import asyncio
import struct

from bleak import BleakScanner, BleakClient
from constants import AUTH_STATES, UUIDS
from Crypto.Cipher import AES
from datetime import datetime, timedelta

RANDOM_BYTE = struct.pack('<2s', b'\x02\x00')
DEFAULT_TIMEOUT = 0.5
with open("secret.txt", "r") as f:
    MAC_ADDRESS, AUTH_KEY = f.read().split("\n")
MAX_CHUNKLENGTH = 17


class Characteristic:
    def __init__(self, char_specifier: str, client: BleakClient) -> None:
        self.char_specifier = char_specifier
        self.client = client

    async def write(self, value, response=False):
        await self.client.write_gatt_char(self.char_specifier, value, response=False)

    async def read(self):
        return await self.client.read_gatt_char(self.char_specifier)

    def _callback(self, handler, data):
        print(f"DEFAULT {handler} {data}")
        pass

    async def init_handler(self):
        await self.client.start_notify(self.char_specifier, self._callback)


class Descriptor:
    def __init__(self, char_specifier: int, client: BleakClient) -> None:
        self.char_specifier = char_specifier
        self.client = client

    async def write(self, value, response=False):
        await self.client.write_gatt_descriptor(self.char_specifier, value)

    async def read(self):
        return await self.client.read_gatt_descriptor(self.char_specifier)


class Wac:
    def __init__(self, address, timeout=0.5) -> None:
        self.address = address
        self.timeout = timeout
        self.state = None
        self.status = None

    async def connect(self):
        device = await BleakScanner.find_device_by_address(
            self.address, cb=dict(use_bdaddr=True)
        )
        self.client = BleakClient(device)
        await self.client.connect()
        return device

    async def createChar(self, char_specifier, special_type=None):
        if special_type == "AUTH":
            return AuthenticateChar(self, char_specifier, self.client)
        elif special_type == "STEP":
            return StepChar(char_specifier, self.client)
        else:
            return Characteristic(char_specifier, self.client)


class StepChar(Characteristic):
    async def read(self):
        a = await super().read()
        steps = struct.unpack('h', a[1:3])[0] if len(a) >= 3 else None
        meters = struct.unpack('h', a[5:7])[0] if len(a) >= 7 else None
        fat_burned = struct.unpack('h', a[2:4])[0] if len(a) >= 4 else None
        calories = struct.unpack('b', a[9:10])[0] if len(a) >= 10 else None
        return {
            "steps": steps,
            "meters": meters,
            "fat_burned": fat_burned,
            "calories": calories
        }


class ActivityGetter:
    """
    + write to notification_decs
    + fetch_char handle initiating/ending device streaming data
    + activity_char handle parsing actual data
    """

    def __init__(self, utc_offset: bytearray, client: BleakClient) -> None:
        temp = datetime.now()
        self.start = datetime(temp.year, temp.month, temp.day)
        self.end = datetime.now()
        self.next_timestamp = self.start
        self.utc_offset = utc_offset
        self.client = client
        self.pkg = 0
        self.lock = asyncio.Lock()

        self.fetch_char = FetchChar(
            self, UUIDS.CHARACTERISTIC_FETCH, client)

        self.activity_char = ActivityChar(
            self, UUIDS.CHARACTERISTIC_ACTIVITY_DATA, client)

    async def set_next_timestamp(self, new_value):
        # async with self.lock:
        self.next_timestamp = new_value

    async def get_next_timestamp(self):
        # async with self.lock:
        return self.next_timestamp

    async def get(self):
        await self.fetch_char.init_handler()
        await self.fetch_char.send_fetch_payload(self.utc_offset)
        await self.activity_char.init_handler()


class ActivityChar(Characteristic):
    def __init__(self, activity_getter: ActivityGetter, char_specifier: str, client: BleakClient) -> None:
        super().__init__(char_specifier, client)
        self.activity_getter = activity_getter
        self.lock = asyncio.Lock()

    async def _callback(self, _, data):
        print(f"LOG [Activity]: {data}")
        if len(data) % 4 == 1:
            self.activity_getter.pkg += 1
            i = 1
            while i < len(data):
                # index = int(self.activity_getter.pkg) * 4 + (i - 1) / 4
                timestamp = (await self.activity_getter.get_next_timestamp()) + timedelta(minutes=1)
                category = struct.unpack("<B", data[i:i + 1])[0]
                intensity = struct.unpack("B", data[i + 1:i + 2])[0]
                steps = struct.unpack("B", data[i + 2:i + 3])[0]
                heart_rate = struct.unpack("B", data[i + 3:i + 4])[0]
                print(timestamp, category, intensity, steps, heart_rate)
                await self.activity_getter.set_next_timestamp(timestamp)
                i += 4

    async def init_handler(self):
        await self.client.start_notify(self.char_specifier, self._callback)


class FetchChar(Characteristic):
    def __init__(self, activity_getter: ActivityGetter, char_specifier: str, client: BleakClient):
        super().__init__(char_specifier, client)
        self.activity_getter = activity_getter

    async def send_fetch_payload(self, utc_offset: bytearray):
        ts = self._pack_timestamp(self.activity_getter.next_timestamp)
        payload = b'\x01\x01' + ts + utc_offset
        await self.write(payload)

    def _pack_timestamp(self, timestamp: datetime):
        year = struct.pack("<H", timestamp.year)
        month = struct.pack("b", timestamp.month)
        day = struct.pack("b", timestamp.day)
        hour = struct.pack("b", timestamp.hour)
        minute = struct.pack("b", timestamp.minute)
        ts = year + month + day + hour + minute
        return ts

    async def _callback(self, _, data):
        print(f"LOG [FETCH]: {data}")
        if data[:3] == b'\x10\x01\x01':
            year = struct.unpack("<H", data[7:9])[0]
            month = struct.unpack("b", data[9:10])[0]
            day = struct.unpack("b", data[10:11])[0]
            hour = struct.unpack("b", data[11:12])[0]
            minute = struct.unpack("b", data[12:13])[0]
            self.activity_getter.next_timestamp = datetime(
                year, month, day, hour, minute)
            print(
                f"actually fetching data from {self.activity_getter.next_timestamp}")
            self.activity_getter.pkg = 0
            await self.write(b'\x02')
        elif data[:3] == b'\x10\x02\x01':
            print(f"stopped at {self.activity_getter.next_timestamp}")
            if self.activity_getter.next_timestamp > self.activity_getter.end - timedelta(minutes=1):
                print("Finished fetching")
                return
            await asyncio.sleep(1)
            t = self.activity_getter.next_timestamp + timedelta(minutes=1)
            print(f"Trigger more communication {t}")
            await self.send_fetch_payload(t)

        elif data[:3] == b'\x10\x02\x04':
            print("No more activity fetch possible")
        else:
            print(f"Unexpected data on handle {str(data)}")

    async def init_handler(self):
        await self.client.start_notify(self.char_specifier, self._callback)


class AuthenticateChar(Characteristic):
    def __init__(self, wac: Wac, char_specifier: str, client: BleakClient):
        super().__init__(char_specifier, client)
        self.wac = wac
        self.auth_key = bytes.fromhex(AUTH_KEY)

    def _encrypt_string_with_key(self, random_string):
        aes = AES.new(self.auth_key, AES.MODE_ECB)
        return aes.encrypt(random_string)

    async def _send_encoded_key(self, data):
        cmd = struct.pack('<2s', b'\x03\x00') + \
            self._encrypt_string_with_key(data)
        send_cmd = struct.pack('<18s', cmd)
        await self.write(send_cmd)
        await asyncio.sleep(self.wac.timeout)

    async def _callback(self, char_specifier, data):
        print(f"LOG [AUTH]: {data}")
        if data[:3] == b'\x10\x01\x01':
            await self.write(RANDOM_BYTE)
        elif data[:3] == b'\x10\x01\x04':
            self.wac.state = AUTH_STATES.KEY_SENDING_FAILED
        elif data[:3] == b'\x10\x02\x01':
            random_string = data[3:]
            await self._send_encoded_key(random_string)
        elif data[:3] == b'\x10\x02\x04':
            self.wac.state = AUTH_STATES.REQUEST_RN_ERROR
        elif data[:3] == b'\x10\x03\x01':
            self.wac.state = AUTH_STATES.AUTH_OK
        elif data[:3] == b'\x10\x03\x04':
            self.wac.status = AUTH_STATES.ENCRYPTION_KEY_FAILED
            # self.device._send_key()
        else:
            self.wac.state = AUTH_STATES.AUTH_FAILED

    async def connect(self):
        await self.write(RANDOM_BYTE)
        await asyncio.sleep(self.wac.timeout)

    async def init_handler(self):
        await self.client.start_notify(self.char_specifier, self._callback)

    async def stop_handler(self):
        print("stopping handler")
        await self.client.stop_notify(self.char_specifier)


class Chunked(Characteristic):
    def __init__(self, char_specifier: str, client: BleakClient) -> None:
        super().__init__(char_specifier, client)

    async def write(self, data_type, data):
        remaining = len(data)
        count = 0
        while (remaining > 0):
            copybytes = min(remaining, MAX_CHUNKLENGTH)
            chunk = b''
            flag = 0
            if remaining <= MAX_CHUNKLENGTH:
                flag |= 0x80
                if count == 0:
                    flag |= 0x40
            elif count > 0:
                flag |= 0x40

            chunk += b'\x00'
            chunk += bytes([flag | data_type])
            chunk += bytes([count & 0xff])
            chunk += data[(count * MAX_CHUNKLENGTH)                          :(count*MAX_CHUNKLENGTH)+copybytes]
            count += 1
            await self.client.write_gatt_char(self.char_specifier, chunk)
            remaining -= copybytes


class MusicChar(Characteristic):
    def __init__(self, char_specifier: str, client: BleakClient, callback) -> None:
        super().__init__(char_specifier, client)
        self._callback = callback

    async def init_handler(self):
        await self.client.start_notify(self.char_specifier, self._callback)


class Music:
    def __init__(self, client: BleakClient) -> None:
        self.chunked = Chunked(
            UUIDS.CHARACTERISTIC_CHUNKED_TRANSFER, client)
        self.music_char = MusicChar(
            UUIDS.CHARACTERISTIC_MUSIC_NOTIFICATION, client, self._callback)

    async def init_handler(self):
        await self.music_char.init_handler()

    async def _callback(self, _, data):
        cmd = data[1:][0] if len(data[1:]) > 0 else None
        if cmd == 0xe0:
            await self.set_music()
        elif cmd == 0xe1:
            print("out")
        elif cmd == 0x00:
            print("play")
        elif cmd == 0x01:
            print("pause")

    async def set_music(self):
        flag = 0x00
        flag |= 0x01
        buf = b''
        null = b'\x00'
        flag |= 0x02
        buf += "self.artist".encode('utf-8') + null
        flag |= 0x04
        buf += "self.album".encode('utf-8') + null
        flag |= 0x08
        buf += "self.track".encode('utf-8') + null
        flag |= 0x10
        buf += struct.pack('<H', 69)
        flag |= 0x40
        buf += bytes([69]) + null
        position = struct.pack('<H', 30)
        buf = bytes([flag, 1, 0x00]) + position + buf
        await self.chunked.write(3, buf)


async def main():
    b = None
    while b is None:
        try:
            a = Wac(MAC_ADDRESS)
            b = await a.connect()
        except Exception:
            print("retrying")
    auth_char = await a.createChar(UUIDS.CHARACTERISTIC_AUTH, special_type="AUTH")
    await auth_char.init_handler()
    await auth_char.connect()
    # auth_desc = Descriptor(97, a.client)
    # await auth_desc.write(b"\x01\x00")
    # try:
    # step = await a.createChar(UUIDS.CHARACTERISTIC_STEPS, "STEP")
    # print(await step.read())

    current_time = await a.createChar(UUIDS.CHARACTERISTIC_CURRENT_TIME)
    current_time = await current_time.read()
    utc_offset = current_time[9:11]

    activity_getter = ActivityGetter(utc_offset, a.client)
    await activity_getter.get()

    # custom_alert = await a.createChar(UUIDS.CHARACTERISTIC_CUSTOM_ALERT)
    # await custom_alert.write(bytes('\x05\x01' + "ur mom" + '\x0a\x0a\x0a' + "omega lul", 'utf-8'), True)

    # music = Music(a.client)
    # await music.init_handler()
    # await music.set_music()

    # await auth_desc.write(b"\x00\x00")

    # except Exception as e:
    #     print(e)
    # await auth.stop_handler()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(main())
    loop.run_forever()
