rule SIGNATURE_BASE_Rottenpotato_Potato : FILE
{
	meta:
		description = "Detects a component of privilege escalation tool Rotten Potato - file Potato.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4a12783c-f58a-518b-a80a-f09f146304cc"
		date = "2017-02-07"
		modified = "2022-12-21"
		reference = "https://github.com/foxglovesec/RottenPotato"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rottenpotato.yar#L10-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "79d2dfd5c2cfd12301c1924dce2ca2a2c3cc070565671c3e0cd69123d2245b1c"
		score = 90
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "59cdbb21d9e487ca82748168682f1f7af3c5f2b8daee3a09544dd58cbf51b0d5"

	strings:
		$x1 = "Potato.exe -ip <ip>" fullword wide
		$x2 = "-enable_httpserver true -enable_spoof true" fullword wide
		$x3 = "/C schtasks.exe /Create /TN omg /TR" fullword wide
		$x4 = "-enable_token true -enable_dce true" fullword wide
		$x5 = "DNS lookup succeeds - UDP Exhaustion failed!" fullword wide
		$x6 = "DNS lookup fails - UDP Exhaustion worked!" fullword wide
		$x7 = "\\obj\\Release\\Potato.pdb" ascii
		$x8 = "function FindProxyForURL(url,host){if (dnsDomainIs(host, \"localhost\")) return \"DIRECT\";" fullword wide
		$s1 = "\"C:\\Windows\\System32\\cmd.exe\" /K start" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of ($x*)) or (2 of them )
}
