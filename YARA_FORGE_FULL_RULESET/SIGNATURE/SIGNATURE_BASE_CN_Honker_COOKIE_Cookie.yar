rule SIGNATURE_BASE_CN_Honker_COOKIE_Cookie : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CooKie.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5f85bb0f-6df2-512c-ba1a-8a74c1a55563"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L205-L220"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f7727160257e0e716e9f0cf9cdf9a87caa986cde"
		logic_hash = "6d942e53a253cb157e535f86ca457c93a6039b2c5ebb3969dc3e271242b478d4"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "-1 union select 1,username,password,4,5,6,7,8,9,10 from admin" fullword ascii
		$s5 = "CooKie.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <360KB and all of them
}
