rule SIGNATURE_BASE_SUSP_Microsoft_Copyright_String_Anomaly_2 : FILE
{
	meta:
		description = "Detects Floxif Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "3257aff0-b923-5e56-b67c-fa676341a102"
		date = "2018-05-11"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_suspicious_strings.yar#L132-L146"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "60bc5d8d0853f474b81d2274a65977a12a481e4b669b38ae47a325eeb60d2735"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"

	strings:
		$s1 = "Microsoft(C) Windows(C) Operating System" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 1 of them
}
