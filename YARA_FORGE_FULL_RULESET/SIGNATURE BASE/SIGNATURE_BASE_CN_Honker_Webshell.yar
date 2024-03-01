rule SIGNATURE_BASE_CN_Honker_Webshell : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Webshell.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "12870766-2b85-522d-9ad8-abba2786caaf"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L487-L503"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c85bd09d241c2a75b4e4301091aa11ddd5ad6d59"
		logic_hash = "d48a10313afcb5a2084229937703bbc11958a5cd11f8f27fbc8dae15ddfd5ed1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Windows NT users: Please note that having the WinIce/SoftIce" fullword ascii
		$s2 = "Do you want to cancel the file download?" fullword ascii
		$s3 = "Downloading: %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <381KB and all of them
}
