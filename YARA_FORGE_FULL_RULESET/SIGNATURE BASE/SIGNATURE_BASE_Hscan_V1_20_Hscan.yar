rule SIGNATURE_BASE_Hscan_V1_20_Hscan : FILE
{
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4183824c-b77f-5500-a962-8d9dc78a9388"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2457-L2474"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		logic_hash = "8e30c366c5d5c34a7b50ba4dec17a46c173196b773fff6965891802bcebeb112"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
		$s3 = ".\\report\\%s-%s.html" fullword ascii
		$s4 = ".\\log\\Hscan.log" fullword ascii
		$s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}
