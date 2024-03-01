import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Be3F393D1Ef0272Aed0E2319C1B5Dd0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2be05341-c7a2-58fd-9211-8d3a912a7d5c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3945-L3956"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a7ff863b07d5ce011bdbcf86a3f562e8201926c138848544559bd1d16597ff95"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7745253a3f65311b84d8f64b74f249364d29e765"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Invincea, Inc." and pe.signatures[i].serial=="0b:e3:f3:93:d1:ef:02:72:ae:d0:e2:31:9c:1b:5d:d0")
}
