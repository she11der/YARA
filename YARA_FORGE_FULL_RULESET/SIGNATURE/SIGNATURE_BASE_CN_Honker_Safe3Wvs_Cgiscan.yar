rule SIGNATURE_BASE_CN_Honker_Safe3Wvs_Cgiscan : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cgiscan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a9f7a195-deb8-5887-bc55-d1b0cac43182"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L343-L358"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f94bbf2034ad9afa43cca3e3a20f142e0bb54d75"
		logic_hash = "990dcede3bb83216af7e72e2a49bc2355ebd45ebd3fc658ba337a285dcdf799f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "httpclient.exe" fullword wide
		$s3 = "www.safe3.com.cn" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <357KB and all of them
}
