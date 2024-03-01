rule CAPE_Qakbot5 : FILE
{
	meta:
		description = "QakBot v5 Payload"
		author = "kevoreilly"
		id = "20a1c312-9570-5b4e-9c39-0281db8fef36"
		date = "2024-02-16"
		modified = "2024-02-16"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/QakBot.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "8afd43d92a90d0986f23ef921254df296279ee8be66c0372fb2f0b348adb2eb8"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "QakBot Payload"
		packed = "f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2"

	strings:
		$loop = {8B 75 ?? 48 8B 4C [2] FF 15 [4] 48 8B 4C [2] 48 8B 01 FF 50 ?? 8B DE 48 8B 4C [2] 48 85 C9 0F 85 [4] EB 4E}
		$conf = {0F B7 1D [4] B9 [2] 00 00 E8 [4] 8B D3 48 89 45 ?? 45 33 C9 48 8D 0D [4] 4C 8B C0 48 8B F8 E8}

	condition:
		uint16(0)==0x5A4D and all of them
}
