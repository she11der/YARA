import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Eee8Cf0A0E4C78Faa03D07470161A90E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a91c84db-99b4-5e24-ba8a-4e009219eb05"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2874-L2885"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "5c14eeeab8cf9797499d23f451a695b443ecc8d3ebbc2edb830ae450e444178c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "32eda5261359e76a4e66da1ba82db7b7a48295d2"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aafabffdbdbcbfcaebdf" and pe.signatures[i].serial=="ee:e8:cf:0a:0e:4c:78:fa:a0:3d:07:47:01:61:a9:0e")
}
