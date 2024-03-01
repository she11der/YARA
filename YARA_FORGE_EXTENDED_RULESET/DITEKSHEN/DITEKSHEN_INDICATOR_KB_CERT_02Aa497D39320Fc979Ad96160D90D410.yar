import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_02Aa497D39320Fc979Ad96160D90D410 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9387010e-94f5-5787-b30f-609d98c48ddf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2287-L2298"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "762b1730c8cfcf5a89e49858723d5701c1fb958eb2cd4da5b240f21763cdabf8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "33e8e72a75d6f424c5a10d2b771254c07a7d9c138e5fea703117fe60951427ae"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MATCHLESS GIFTS, INC." and pe.signatures[i].serial=="02:aa:49:7d:39:32:0f:c9:79:ad:96:16:0d:90:d4:10")
}
