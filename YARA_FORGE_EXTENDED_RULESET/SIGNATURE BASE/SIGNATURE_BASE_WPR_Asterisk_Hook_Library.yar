import "pe"

rule SIGNATURE_BASE_WPR_Asterisk_Hook_Library : FILE
{
	meta:
		description = "Windows Password Recovery - file ast64.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "03c20c9d-bb8f-53f6-9cb5-9b059fb24949"
		date = "2017-03-15"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3550-L3572"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6bb75cb8c3ba18a34f4651532060154608c78e6f748148226da4416ad1171124"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "225071140e170a46da0e57ce51f0838f4be00c8f14e9922c6123bee4dffde743"
		hash2 = "95ec84dc709af990073495082d30309c42d175c40bd65cad267e6f103852a02d"

	strings:
		$s1 = "ast64.dll" fullword ascii
		$s2 = "ast.dll" fullword wide
		$s3 = "c:\\%s.lvc" fullword ascii
		$s4 = "c:\\%d.lvc" fullword ascii
		$s5 = "Asterisk Hook Library" fullword wide
		$s6 = "?Ast_StartRd64@@YAXXZ" fullword ascii
		$s7 = "Global\\{1374821A-281B-9AF4-%04X-12345678901234}" fullword ascii
		$s8 = "2004-2013 Passcape Software" fullword wide
		$s9 = "Global\\Passcape#6712%04X" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them )
}
