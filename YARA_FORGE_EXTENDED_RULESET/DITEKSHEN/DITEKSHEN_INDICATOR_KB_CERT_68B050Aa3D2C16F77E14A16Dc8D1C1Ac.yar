import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_68B050Aa3D2C16F77E14A16Dc8D1C1Ac : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "b49d3f1d-34b4-578e-ab36-b0744deef548"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1006-L1017"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9de23897fbfe3c4a6d649558d1d71f890117ec80967bc5bd975aa6f33576c702"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c757e09e7dc5859dbd00b0ccfdd006764c557a3d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLOW POKE LTD" and pe.signatures[i].serial=="68:b0:50:aa:3d:2c:16:f7:7e:14:a1:6d:c8:d1:c1:ac")
}
