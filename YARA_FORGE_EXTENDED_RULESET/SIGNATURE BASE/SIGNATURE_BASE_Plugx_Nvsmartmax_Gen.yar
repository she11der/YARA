rule SIGNATURE_BASE_Plugx_Nvsmartmax_Gen : FILE
{
	meta:
		description = "Threat Group 3390 APT Sample - PlugX NvSmartMax Generic"
		author = "Florian Roth (Nextron Systems)"
		id = "5ecd25a8-9717-527f-bb6e-3259b9a60458"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "http://snip.ly/giNB"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_threatgroup_3390.yar#L126-L154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7795b0d978f9447a6cee808708d65992447e359539a8fe64331c06ad46ff7491"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "718fc72942b9b706488575c0296017971170463f6f40fa19b08fc84b79bf0cef"
		hash2 = "1c0379481d17fc80b3330f148f1b87ff613cfd2a6601d97920a0bcd808c718d0"
		hash3 = "555952aa5bcca4fa5ad5a7269fece99b1a04816d104ecd8aefabaa1435f65fa5"
		hash4 = "71f7a9da99b5e3c9520bc2cc73e520598d469be6539b3c243fb435fe02e44338"
		hash5 = "65bbf0bd8c6e1ccdb60cf646d7084e1452cb111d97d21d6e8117b1944f3dc71e"

	strings:
		$s0 = "NvSmartMax.dll" fullword ascii
		$s1 = "NvSmartMax.dll.url" fullword ascii
		$s2 = "Nv.exe" fullword ascii
		$s4 = "CryptProtectMemory failed" fullword ascii
		$s5 = "CryptUnprotectMemory failed" fullword ascii
		$s7 = "r%.*s(%d)%s" fullword wide
		$s8 = " %s CRC " fullword wide
		$op0 = { c6 05 26 49 42 00 01 eb 4a 8d 85 00 f8 ff ff 50 }
		$op1 = { 8d 85 c8 fe ff ff 50 8d 45 c8 50 c6 45 47 00 e8 }
		$op2 = { e8 e6 65 00 00 50 68 10 43 41 00 e8 56 84 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of ($s*) and 1 of ($op*)
}
