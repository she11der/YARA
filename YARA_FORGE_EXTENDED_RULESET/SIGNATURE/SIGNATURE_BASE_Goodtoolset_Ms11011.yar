rule SIGNATURE_BASE_Goodtoolset_Ms11011 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "689b7ea3-6707-5f99-8232-438d903d414d"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1626-L1642"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
		logic_hash = "99dd27eba7da44c71098446e17abfe626de91e899e28c2d2e99e7b54b9e0c825"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s3 = "Not supported." fullword wide
		$s4 = "SystemDefaultEUDCFont" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
