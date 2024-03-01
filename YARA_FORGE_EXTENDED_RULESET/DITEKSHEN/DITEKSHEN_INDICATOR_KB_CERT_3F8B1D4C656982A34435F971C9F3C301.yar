import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3F8B1D4C656982A34435F971C9F3C301 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7bafe9c8-7ec5-5847-81dc-2f2d0753f784"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5296-L5307"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "95fd60c5f236b06fca308696dfe3e3aeb3aa6f255c6030d44822dc33a7c4c917"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f12a12ac95e5c4fa9948dd743cc0e81e46c5222e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Word" and pe.signatures[i].serial=="3f:8b:1d:4c:65:69:82:a3:44:35:f9:71:c9:f3:c3:01")
}
