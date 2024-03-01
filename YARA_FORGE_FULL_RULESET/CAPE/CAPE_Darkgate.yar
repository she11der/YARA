rule CAPE_Darkgate
{
	meta:
		description = "DarkGate Payload"
		author = "enzok"
		id = "ce81f452-4096-51d6-97cc-624f9fbefa86"
		date = "2024-02-26"
		modified = "2024-02-26"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/DarkGate.yar#L1-L16"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "25c0e77a83676c6a18445f8df0b1f7a9148de5f64eeb532f9a4f4d4652dd8191"
		score = 75
		quality = 70
		tags = ""
		cape_type = "DarkGate Payload"

	strings:
		$part1 = {8B 55 ?? 8A 4D ?? 80 E1 3F C1 E1 02 8A 5D ?? 80 E3 30 81 E3 FF [3] C1 EB 04 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
		$part2 = {8B 55 ?? 8A 4D ?? 80 E1 0F C1 E1 04 8A 5D ?? 80 E3 3C 81 E3 FF [3] C1 EB 02 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
		$part3 = {8B 55 ?? 8A 4D ?? 80 E1 03 C1 E1 06 8A 5D ?? 80 E3 3F 02 CB 88 4C 10 FF FF 45}
		$alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
		$config1 = {B9 01 04 00 00 E8 [4] 8D 45}
		$config2 = {8B 55 ?? 8D 45 ?? E8 [4] 8D 45 ?? 5? B? 06 00 00 00 B? 01 00 00 00 8B 45 ?? E8 [4] 8B 45 ?? B? [4] E8 [4] 75}

	condition:
		($alphabet) and ( any of ($part*) or all of ($config*))
}
