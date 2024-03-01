import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_07Cf63Bdccc15C55E5Ce785Bdfbeaacf : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7bdc16ed-ff95-5e96-bfe9-ad326c77c82a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2599-L2610"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "1fdd8f6535bf5a78fcd7e33475a650914053f1391fe04f885e9e5a84452bfe5a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3306df7607bed04187d23c1eb93adf2998e51d01"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REITSUPER ESTATE LLC" and pe.signatures[i].serial=="07:cf:63:bd:cc:c1:5c:55:e5:ce:78:5b:df:be:aa:cf")
}
