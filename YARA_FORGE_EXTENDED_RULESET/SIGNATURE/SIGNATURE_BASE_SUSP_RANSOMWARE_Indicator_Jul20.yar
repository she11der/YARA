rule SIGNATURE_BASE_SUSP_RANSOMWARE_Indicator_Jul20 : FILE
{
	meta:
		description = "Detects ransomware indicator"
		author = "Florian Roth (Nextron Systems)"
		id = "6036fdfd-8474-5d79-ac75-137ac2efdc77"
		date = "2020-07-28"
		modified = "2023-12-05"
		reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_ransom_generic.yar#L2-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3dd1b29f45afba16d58619416e0d420acd38fb8ae1fc846035229a27b9e5c9d9"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
		hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
		hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"

	strings:
		$ = "Decrypt.txt" ascii wide
		$ = "DecryptFiles.txt" ascii wide
		$ = "Decrypt-Files.txt" ascii wide
		$ = "DecryptFilesHere.txt" ascii wide
		$ = "DECRYPT.txt" ascii wide
		$ = "DecryptFiles.txt" ascii wide
		$ = "DECRYPT-FILES.txt" ascii wide
		$ = "DecryptFilesHere.txt" ascii wide
		$ = "DECRYPT_INSTRUCTION.TXT" ascii wide
		$ = "FILES ENCRYPTED.txt" ascii wide
		$ = "DECRYPT MY FILES" ascii wide
		$ = "DECRYPT-MY-FILES" ascii wide
		$ = "DECRYPT_MY_FILES" ascii wide
		$ = "DECRYPT YOUR FILES" ascii wide
		$ = "DECRYPT-YOUR-FILES" ascii wide
		$ = "DECRYPT_YOUR_FILES" ascii wide
		$ = "DECRYPT FILES.txt" ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <1400KB and 1 of them
}
