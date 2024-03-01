rule SIGNATURE_BASE_Msfpayloads_Msf_10 : FILE
{
	meta:
		description = "Metasploit Payloads - file msf.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3bc3b66a-9f8a-55c2-ae2a-00faa778cef7"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L254-L269"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c772fdc40e110ef1287da680dc4ef1718b86856abab4d814ec7bc2ee1e7808ee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"

	strings:
		$s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 }
		$s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b }
		$s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
