import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1F55Ae3Fca38827Cde6Cc7Ca1C0D2731 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8a32fa5d-671e-5012-9de1-6afc21751b94"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3269-L3280"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "1aa7c6c5430f196d1031acabfe141c30044c23c4119619752c50f4665966606e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a279fa4186ef598c5498ba5c0037c7bd4bd57272"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fcceaeafbbdccccddfbbb" and pe.signatures[i].serial=="1f:55:ae:3f:ca:38:82:7c:de:6c:c7:ca:1c:0d:27:31")
}
