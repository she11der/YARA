rule SIGNATURE_BASE_Hydra_7_4_1_Hydra : FILE
{
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "cf692bea-091d-5be0-a012-caba01e96dde"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1814-L1832"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"
		logic_hash = "f52696cbf7355c982d1a1e0c73dce65324845c5ffc13c541e326720332b4788d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
		$s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
		$s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
		$s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 2 of them
}
