import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_066226Cf6A4D8Ae1100961A0C5404Ff9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "75db8056-a5da-5db4-a837-84c5cc05f0fc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L419-L430"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0b7fa450d143de99650d0364e461178ad4e0b147b19dae53b59928b2a17c9b6d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8c762918a58ebccb1713720c405088743c0d6d20"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO MEP" and pe.signatures[i].serial=="06:62:26:cf:6a:4d:8a:e1:10:09:61:a0:c5:40:4f:f9")
}
