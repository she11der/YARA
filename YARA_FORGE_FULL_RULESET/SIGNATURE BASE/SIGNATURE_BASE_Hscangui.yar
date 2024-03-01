rule SIGNATURE_BASE_Hscangui : FILE
{
	meta:
		description = "Chinese Hacktool Set - file hscangui.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f0993510-70ee-52c6-a7b8-e023eb4b33ee"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2380-L2396"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "af8aced0a78e1181f4c307c78402481a589f8d07"
		logic_hash = "9c0eb87dcf8aa107b5289d196650aebcf49c24f57a317de0afdadd61fb5bb5b7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "http://www.cnhonker.com" fullword ascii
		$s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
		$s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <220KB and 2 of them
}
