import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E5D20477E850C9F35C5C47123Ef34271 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "c8777008-b15f-58c8-9172-f54a4864d2cc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1218-L1229"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "984f6dba8613ca43a9ffdcba63e57516bd2c6df02698b87aa4a080f89cc6abc0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d11431836db24dcc3a17de8027ab284a035f2e4f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\x89\\xBE\\xE5\\x8B\\x92\\xD0\\x92\\xE8\\xB4\\x9D\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xE8\\xB4\\x9D\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\xB4\\x9D\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92" and pe.signatures[i].serial=="00:e5:d2:04:77:e8:50:c9:f3:5c:5c:47:12:3e:f3:42:71")
}
