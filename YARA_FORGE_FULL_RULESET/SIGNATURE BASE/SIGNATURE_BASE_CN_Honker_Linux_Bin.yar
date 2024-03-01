rule SIGNATURE_BASE_CN_Honker_Linux_Bin : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file linux_bin"
		author = "Florian Roth (Nextron Systems)"
		id = "3c56a4a8-6392-517c-a16e-63785799acb9"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L239-L254"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "26e71e6ebc6a3bdda9467ce929610c94de8a7ca0"
		logic_hash = "d02fcf23e46a0b6d44c382e34d73ef6239b6a1afc690e417aa0e6b0898e277c0"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "client.sin_port = htons(atoi(argv[3]));" fullword ascii
		$s2 = "printf(\"\\n\\n*********Waiting Client connect*****\\n\\n\");" fullword ascii

	condition:
		filesize <20KB and all of them
}
