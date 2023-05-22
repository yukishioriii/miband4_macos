

import asyncio
import struct

from bleak import BleakScanner, BleakClient
from constants import AUTH_STATES, UUIDS
from Crypto.Cipher import AES

RANDOM_BYTE = struct.pack('<2s', b'\x02\x00')

with open("secret.txt", "r") as f:
    MAC_ADDRESS, AUTH_KEY = f.read().split("\n")


class Characteristic:
    def __init__(self, char_specifier: str, client: BleakClient) -> None:
        self.char_specifier = char_specifier
        self.client = client

    async def write(self, value):
        await self.client.write_gatt_char(self.char_specifier, value)

    async def read(self):
        return await self.client.read_gatt_char(self.char_specifier)


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
        # why only 1 byte??
        calories = struct.unpack('b', a[9:10])[0] if len(a) >= 10 else None
        return {
            "steps": steps,
            "meters": meters,
            "fat_burned": fat_burned,
            "calories": calories
        }


class AuthenticateChar(Characteristic):
    def __init__(self, wac: Wac, char_specifier: str, client: BleakClient):
        super().__init__(char_specifier, client)
        self.wac = wac
        self.auth_key = bytes.fromhex(AUTH_KEY)

    def _encrypt_string_with_key(self, random_string):
        aes = AES.new(self.auth_key, AES.MODE_ECB)
        return aes.encrypt(random_string)

    async def _send_encoded_key(self, data):
        cmd = struct.pack('<2s', b'\x03\x00') + self._encrypt_string_with_key(data)
        send_cmd = struct.pack('<18s', cmd)
        await self.write(send_cmd)
        await asyncio.sleep(self.wac.timeout)

    async def callback(self, char_specifier, data):
        print(f"LOG [AUTH] CALLBACK: {data}")
        if data[:3] == b'\x10\x01\x01':
            self.write(RANDOM_BYTE)
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
        await self.client.start_notify(self.char_specifier, self.callback)

    async def stop_handler(self):
        print("stopping handler")
        await self.client.stop_notify(self.char_specifier)


async def main():
    b = None
    while b is None:
        try:
            print("scanning for 5 seconds, please wait...")
            a = Wac(MAC_ADDRESS)
            b = await a.connect()
        except Exception:
            print("retrying")
    serial_number = await a.createChar(UUIDS.SERIAL_NUMBER)
    auth = await a.createChar(UUIDS.CHARACTERISTIC_AUTH, special_type="AUTH")
    print(await serial_number.read())
    await auth.init_handler()
    await auth.connect()
    try:
        step = await a.createChar(UUIDS.CHARACTERISTIC_STEPS, "STEP")
        print(await step.read())
    except Exception as e:
        print(e)
    # await auth.stop_handler()


if __name__ == "__main__":
    asyncio.run(main())
