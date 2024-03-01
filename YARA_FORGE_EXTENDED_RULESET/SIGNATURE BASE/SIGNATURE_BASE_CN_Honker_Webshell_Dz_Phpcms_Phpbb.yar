rule SIGNATURE_BASE_CN_Honker_Webshell_Dz_Phpcms_Phpbb : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file dz_phpcms_phpbb.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "f7e5413f-a7c9-51d4-8422-30c3e2462be2"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L264-L281"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "33f23c41df452f8ca2768545ac6e740f30c44d1f"
		logic_hash = "1455df58f51c3ae7558b89c940d97ea5870f261217b2a09727bb6678bcbd5500"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii
		$s2 = "function test_1($password)" fullword ascii
		$s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
		$s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii

	condition:
		filesize <22KB and all of them
}
