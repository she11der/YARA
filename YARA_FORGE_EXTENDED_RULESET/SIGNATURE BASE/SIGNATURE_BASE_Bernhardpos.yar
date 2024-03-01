rule SIGNATURE_BASE_Bernhardpos
{
	meta:
		description = "BernhardPOS Credit Card dumping tool"
		author = "Nick Hoffman / Jeremy Humble"
		id = "9b9e1507-cf1b-5653-beaa-458205e367c3"
		date = "2015-07-14"
		modified = "2023-12-05"
		reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_bernhard_pos.yar#L1-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e49820ef02ba5308ff84e4c8c12e7c3d"
		logic_hash = "c00f2fda5a391b44767d918945069f18cef084dd4dc6aa94d8f945bf97ac462a"
		score = 70
		quality = 85
		tags = ""

	strings:
		$shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
		$mutex_name = "OPSEC_BERNHARD"
		$build_path = "C:\\bernhard\\Debug\\bernhard.pdb"
		$string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }

	condition:
		any of them
}