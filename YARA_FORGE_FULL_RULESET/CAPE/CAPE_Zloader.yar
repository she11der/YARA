rule CAPE_Zloader : FILE
{
	meta:
		description = "Zloader Payload"
		author = "kevoreilly, enzok"
		id = "a26e39f6-82b8-5b59-9f84-9ec0b1c85fff"
		date = "2024-01-18"
		modified = "2024-01-18"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/Zloader.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		hash = "adbd0c7096a7373be82dd03df1aae61cb39e0a155c00bbb9c67abc01d48718aa"
		logic_hash = "0213359a331499dea0aa35a4001782dac9915f91e6b8c977ff8ee4f10f2b5050"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Zloader Payload"

	strings:
		$rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
		$decrypt_conf = {83 C4 04 84 C0 74 5? E8 [4] E8 [4] E8 [4] E8 [4] ?8 [4] ?8 [4] ?8}
		$decrypt_conf_1 = {48 8d [5] [0-6] e8 [4] 48 [3-4] 48 [3-4] 48 [6] E8}
		$decrypt_key_1 = {66 89 C2 4? 8D 0D [3] 00 4? B? FC 03 00 00 E8 [4] 4? 83 C4 [1-2] C3}

	condition:
		uint16(0)==0x5A4D and 2 of them
}
