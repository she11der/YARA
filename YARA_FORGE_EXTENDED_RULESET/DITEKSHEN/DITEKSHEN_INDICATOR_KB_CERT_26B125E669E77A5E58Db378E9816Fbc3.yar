import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_26B125E669E77A5E58Db378E9816Fbc3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "18985965-9e26-526c-9354-20667d472615"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L915-L926"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "859793bfeba55c9912a1e18db86cd391d4c4981f4be11f3a53d887d429882671"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "900aa9e6ff07c6528ecd71400e6404682e812017"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FLOWER DELI LTD" and pe.signatures[i].serial=="26:b1:25:e6:69:e7:7a:5e:58:db:37:8e:98:16:fb:c3")
}
