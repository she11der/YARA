import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D2Caf7908Aaebfa1A8F3E2136Fece024 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "043a598d-8b84-597f-ac2e-035cc9ccef77"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1988-L1999"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2c8a322e687ed575e66ff308bcf0950ab87bc5ac3ab561c8cc3d81e9181ac708"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "82baf9b781d458a29469e5370bc9752ebef10f3f8ea506ca6dd04ea5d5f70334"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FANATOR, OOO" and pe.signatures[i].serial=="00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24")
}
