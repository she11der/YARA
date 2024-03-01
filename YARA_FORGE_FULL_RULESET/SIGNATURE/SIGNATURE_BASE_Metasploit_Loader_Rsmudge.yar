rule SIGNATURE_BASE_Metasploit_Loader_Rsmudge : FILE
{
	meta:
		description = "Detects a Metasploit Loader by RSMudge - file loader.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4d8a215e-a942-5df9-bdad-0c4158992429"
		date = "2016-04-20"
		modified = "2023-12-05"
		reference = "https://github.com/rsmudge/metasploit-loader"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_loader_rsmudge.yar#L10-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "50b1898e3087a5e0876b87179252c452af48e00bbef52297060d70acd90d0133"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "afe34bfe2215b048915b1d55324f1679d598a0741123bc24274d4edc6e395a8d"

	strings:
		$s1 = "Could not resolve target" fullword ascii
		$s2 = "Could not connect to target" fullword ascii
		$s3 = "%s [host] [port]" fullword ascii
		$s4 = "ws2_32.dll is out of date." fullword ascii
		$s5 = "read a strange or incomplete length value" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (3 of ($s*))) or ( all of them )
}
