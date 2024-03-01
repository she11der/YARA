import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_309368B122Ab63103Dddd4Ad6321A82C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a9c2fa86-506e-503a-a864-8368f63662c4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7353-L7365"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "37a39d63e2bce6d4ce501e3032ee12fe8c5b39e8d8cb0f3e0c6d0be375bcffc8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1370de077e2ba2065478dee8075b16c0e5a5e862"
		hash1 = "b7376049b73feb5bc677a02e4040f2ec7e7302456db9eac35c71072dd95557eb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Systems Accounting Limited" and pe.signatures[i].serial=="30:93:68:b1:22:ab:63:10:3d:dd:d4:ad:63:21:a8:2c")
}
