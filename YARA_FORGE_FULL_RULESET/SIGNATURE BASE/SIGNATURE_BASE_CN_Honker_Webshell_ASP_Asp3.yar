rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Asp3 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp3.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "0cb01c07-b424-532d-8aef-5ec25dfe3f19"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L162-L177"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
		logic_hash = "e5f30a445be30c491e669c633bf2df08cbfb1017ecfc91f9ed83275550488304"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii
		$s2 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", Tru" ascii

	condition:
		filesize <444KB and all of them
}
