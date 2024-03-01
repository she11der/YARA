rule SIGNATURE_BASE_Apt_Hellsing_Msgertype2 : FILE
{
	meta:
		description = "detection for Hellsing msger type 2 implants"
		author = "Kaspersky Lab"
		id = "98f151de-c1c2-56c1-8c64-5d1f437e0742"
		date = "2015-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_hellsing_kaspersky.yar#L99-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "232e4dfd8d236da223240d9a4ec3f8bfa635d51d7376ff19dfa5579af31fc47f"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		filetype = "PE"

	strings:
		$a1 = "%s\\system\\%d.txt"
		$a2 = "_msger"
		$a3 = "http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
		$a4 = "http://%s/data/%s.1000001000"
		$a5 = "/lib/common.asp?action=user_upload&file="
		$a6 = "%02X-%02X-%02X-%02X-%02X-%02X"

	condition:
		uint16(0)==0x5a4d and (4 of ($a*)) and filesize <500000
}
