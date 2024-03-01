import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C4188D6B70B4Bd3B977B19Abd04C1157 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f5b2b4cf-39a5-59c6-860e-b738a2acfd89"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5871-L5882"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6ed619e18d749c2524ad3c1ddc3268f9ddf77feb3a3f2c5954ae4e7124d63c75"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "90fefd18c677d6e5ac6db969a7247e3eb0b018df"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PRESTO Co., s.r.o." and pe.signatures[i].serial=="00:c4:18:8d:6b:70:b4:bd:3b:97:7b:19:ab:d0:4c:11:57")
}
