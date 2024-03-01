rule CAPE_Darkgate
{
	meta:
		description = "DarkGate Payload"
		author = "enzok"
		id = "1190d1de-2641-5151-a994-e1354b5bce2a"
		date = "2023-10-01"
		modified = "2023-10-01"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/data/yara/CAPE/DarkGate.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/LICENSE"
		logic_hash = "84ff1f8c44884e8e932e4e224167182299c4ac4485e3346e9c14822f3043849c"
		score = 75
		quality = 70
		tags = ""
		cape_type = "DarkGate Payload"

	strings:
		$part1 = {8B 55 ?? 8A 4D ?? 80 E1 3F C1 E1 02 8A 5D ?? 80 E3 30 81 E3 FF [3] C1 EB 04 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
		$part2 = {8B 55 ?? 8A 4D ?? 80 E1 0F C1 E1 04 8A 5D ?? 80 E3 3C 81 E3 FF [3] C1 EB 02 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
		$part3 = {8B 55 ?? 8A 4D ?? 80 E1 03 C1 E1 06 8A 5D ?? 80 E3 3F 02 CB 88 4C 10 FF FF 45}
		$alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="

	condition:
		($alphabet) and any of ($part*)
}
