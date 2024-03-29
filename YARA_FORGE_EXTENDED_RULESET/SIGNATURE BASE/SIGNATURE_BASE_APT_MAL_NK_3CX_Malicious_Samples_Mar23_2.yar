import "pe"

rule SIGNATURE_BASE_APT_MAL_NK_3CX_Malicious_Samples_Mar23_2 : FILE
{
	meta:
		description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
		author = "Florian Roth (Nextron Systems)"
		id = "bf3597ff-d62b-5d21-9c9b-e46e685284cf"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://twitter.com/dan__mayer/status/1641170769194672128?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mal_3cx_compromise_mar23.yar#L32-L54"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dec8310c1f5b304a755737a0005bb33b1762f21ed380b2b98b0f5427948ab930"
		score = 80
		quality = 60
		tags = "FILE"
		hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"

	strings:
		$s1 = "raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
		$s2 = "https://raw.githubusercontent.com/IconStorages" wide fullword
		$s3 = "icon%d.ico" wide fullword
		$s4 = "__tutmc" ascii fullword
		$op1 = { 2d ee a1 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 46 a0 00 00 44 8b 05 7f a2 00 00 e8 0a 0e 00 00 }
		$op4 = { 4c 8d 5c 24 71 0f 57 c0 48 89 44 24 60 89 44 24 68 41 b9 15 cd 5b 07 0f 11 44 24 70 b8 b1 68 de 3a 41 ba a4 7b 93 02 }
		$op5 = { f7 f3 03 d5 69 ca e8 03 00 00 ff 15 c9 0a 02 00 48 8d 44 24 30 45 33 c0 4c 8d 4c 24 38 48 89 44 24 20 }

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 3 of them or 5 of them
}
