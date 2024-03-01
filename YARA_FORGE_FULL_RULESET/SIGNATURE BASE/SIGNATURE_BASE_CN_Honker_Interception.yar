rule SIGNATURE_BASE_CN_Honker_Interception : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Interception.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "40d350e5-c6af-58e2-a1d8-f9516af5f869"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L291-L306"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ea813aed322e210ea6ae42b73b1250408bf40e7a"
		logic_hash = "d1ae5f8ff21659b95f6e62b1d5e3ec15b122a2b5889e8984f3d9f6d2fa938d17"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = ".\\dat\\Hookmsgina.dll" fullword ascii
		$s5 = "WinlogonHackEx " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <160KB and all of them
}
