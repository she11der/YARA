rule TRELLIX_ARC_RANSOM_RYUK_May2021 : ransomware FILE
{
	meta:
		description = "Rule to detect latest May 2021 compiled Ryuk variant"
		author = "Marc Elias | McAfee ATR Team"
		id = "6e415a9e-7373-50a8-ad57-f95220faed9c"
		date = "2021-05-21"
		modified = "2021-07-12"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Ryuk.yar#L91-L113"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "8f368b029a3a5517cb133529274834585d087a2d3a5875d03ea38e5774019c8a"
		logic_hash = "b379c1182e60ce8c777668386d8cbd08350dd2363770dec56502bf44aaf5d7f6"
		score = 50
		quality = 70
		tags = "FILE"
		version = "0.1"

	strings:
		$ryuk_filemarker = "RYUKTM" fullword wide ascii
		$sleep_constants = { 68 F0 49 02 00 FF (15|D1) [0-4] 68 ?? ?? ?? ?? 6A 01 }
		$icmp_echo_constants = { 68 A4 06 00 00 6A 44 8D [1-6] 5? 6A 00 6A 20 [5-20] FF 15 }

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x00004550 and filesize <200KB and ($ryuk_filemarker or ($sleep_constants and $icmp_echo_constants))
}
