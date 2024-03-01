import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ce40906451925405D0F6C130Db461F71 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "5e858504-b1c4-579e-b0e8-f6cf4f434672"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1166-L1177"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "02b03b18942cff20ddce429f7be7cc9e54dfbf4884c79c7438c9b9d4415c5b93"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "af79bbdb4fa0724f907343e9b1945ffffb34e9b3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xD0\\xA5\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x96\\xAF\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xD0\\xA5\\xE6\\x96\\xAF\\xD0\\xA5\\xD0\\xA5\\xE6\\x96\\xAF\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x9D\\xB0" and pe.signatures[i].serial=="00:ce:40:90:64:51:92:54:05:d0:f6:c1:30:db:46:1f:71")
}
