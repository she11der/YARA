rule CAPE_Carbanak : FILE
{
	meta:
		description = "Carnbanak Payload"
		author = "enzok"
		id = "361f3685-bf6c-5c31-b2d5-0247f41063f1"
		date = "2023-11-30"
		modified = "2023-11-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/data/yara/CAPE/Carbanak.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/LICENSE"
		logic_hash = "4b8a5f6b92448fb4918c3c7a6b20cf98095ffbe21537d97b12690302295e0cba"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Carbanak Payload"

	strings:
		$sboxinit = {0F BE 02 4? 8D 05 [-] 4? 8D 4D ?? E8 [3] 00 33 F6 4? 8D 5D ?? 4? 63 F8 8B 45 ?? B? B1 E3 14 06}
		$decode_string = {0F BE 03 FF C9 83 F8 20 7D ?? B? 1F [3] 4? 8D 4A E2 EB ?? 3D 80 [3] 7D ?? B? 7F [3] 4? 8D 4A A1 EB ?? B? FF [3] 4? 8D 4A 81}

	condition:
		uint16(0)==0x5A4D and all of them
}
