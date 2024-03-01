import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C167F04B338B1E8747B92C2197403C43 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d838e09b-e2f2-585a-a33d-bfe34f989e77"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L107-L118"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "008fe748c7956c1885c7d7e3a843d2310c17b7552dbbe9b4750809a5642d7ca6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7af7df92fa78df96d83b3c0fd9bee884740572f9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and pe.signatures[i].serial=="00:c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43")
}
