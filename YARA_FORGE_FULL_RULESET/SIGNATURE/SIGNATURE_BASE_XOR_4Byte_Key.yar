rule SIGNATURE_BASE_XOR_4Byte_Key : FILE
{
	meta:
		description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
		author = "Florian Roth (Nextron Systems)"
		id = "77850332-87ce-5ed3-bb09-88e91e5bb5f6"
		date = "2015-12-15"
		modified = "2023-12-05"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_derusbi.yar#L98-L121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "61cbdac3fd9a486d85261234698f33aa04d505b32dfec731de6fc61d103bf609"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }

	condition:
		uint16(0)==0x5a4d and filesize <900KB and all of them
}
