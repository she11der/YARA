import "pe"

rule SIGNATURE_BASE_Wiltedtulip_Matryoshka_RAT : FILE
{
	meta:
		description = "Detects Matryoshka RAT used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "e851e212-bb71-55c9-9bc1-0041bb04bef5"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_wilted_tulip.yar#L270-L289"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9e878d9e3dc3f2050e52a046038f4f855b5b777948d928e0bc6d7a98fc0a7119"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6f208473df0d31987a4999eeea04d24b069fdb6a8245150aa91dfdc063cd64ab"
		hash2 = "6cc1f4ecd28b833c978c8e21a20a002459b4a6c21a4fbaad637111aa9d5b1a32"

	strings:
		$s1 = "%S:\\Users\\public" fullword wide
		$s2 = "ntuser.dat.swp" fullword wide
		$s3 = "Job Save / Load Config" fullword wide
		$s4 = ".?AVPSCL_CLASS_JOB_SAVE_CONFIG@@" fullword ascii
		$s5 = "winupdate64.com" fullword ascii
		$s6 = "Job Save KeyLogger" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 3 of them )
}
