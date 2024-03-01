import "pe"

rule SIGNATURE_BASE_Editkeylogreadme
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "db083c04-9e5c-5cfd-b4d4-eecf28191b6b"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1825-L1843"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "dfa90540b0e58346f4b6ea12e30c1404e15fbe5a"
		logic_hash = "a58a2336e7d714a2e7f60eec8dacbee9a7190552dd791d8b6eba084ffaf0904a"
		score = 60
		quality = 35
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "editKeyLog.exe KeyLog.exe," fullword ascii
		$s1 = "WinEggDrop.DLL" fullword ascii
		$s2 = "nc.exe" fullword ascii
		$s3 = "KeyLog.exe" fullword ascii
		$s4 = "EditKeyLog.exe" fullword ascii
		$s5 = "wineggdrop" fullword ascii

	condition:
		3 of them
}
