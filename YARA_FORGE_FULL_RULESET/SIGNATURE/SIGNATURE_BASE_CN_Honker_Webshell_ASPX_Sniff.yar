rule SIGNATURE_BASE_CN_Honker_Webshell_ASPX_Sniff : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "8cf47d71-1b97-5967-ad70-2ea6fad7cc29"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L179-L194"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e246256696be90189e6d50a4ebc880e6d9e28dfd"
		logic_hash = "198442e75422055e7d65c5d1aef55819036a99077aa79dbd5006ba97c4fe4af8"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
		$s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii

	condition:
		filesize <91KB and all of them
}
