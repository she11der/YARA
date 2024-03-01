rule SIGNATURE_BASE_CN_Honker_Havij_Havij : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Havij.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b3640a32-b546-58c9-abb1-3da60dc6633c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L433-L448"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0d8b275bd1856bc6563dd731956f3b312e1533cd"
		logic_hash = "e8aff3e1e536cd35b10bdaab4818542bce284e7ed3aa7ef1920763669faf4c8a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "User-Agent: %Inject_Here%" fullword wide
		$s2 = "BACKUP database master to disk='d:\\Inetpub\\wwwroot\\1.zip'" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
