rule SIGNATURE_BASE_CN_Honker_Wwwscan_1_Wwwscan : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8b6a94a3-6f9c-59b2-931b-c06701b95d59"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L222-L237"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6bed45629c5e54986f2d27cbfc53464108911026"
		logic_hash = "7b0b6bbcba49c8f950ea3cf5a364059ba784c87a41eba6d825a9ca4e3a07bfbc"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s3 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <180KB and all of them
}
