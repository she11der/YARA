import "pe"

rule DITEKSHEN_INDICATOR_TOOL_ENUM_Sharpshares : FILE
{
	meta:
		description = "Detects SharpShares multithreaded C# .NET Assembly to enumerate accessible network shares in a domain"
		author = "ditekSHen"
		id = "1da53e34-21a3-5b3c-885e-dcc8814ac3c8"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L1290-L1305"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8b35d6a692814e1b27ffc1db4ab124bf621c156aaf57f24796c422ec95a85715"
		score = 75
		quality = 25
		tags = "FILE"

	strings:
		$s1 = "SharpShares." ascii wide
		$s2 = "GetComputerShares" fullword ascii
		$s3 = "userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2" wide
		$s4 = "GetAllShares" fullword ascii
		$s5 = "stealth:" wide
		$s6 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))" fullword wide
		$s7 = /\/targets|ldap|threads/ wide
		$s8 = "entriesread" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
