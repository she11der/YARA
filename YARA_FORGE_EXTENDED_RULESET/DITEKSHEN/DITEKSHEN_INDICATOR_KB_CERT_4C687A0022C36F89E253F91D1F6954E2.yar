import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4C687A0022C36F89E253F91D1F6954E2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d4b03832-60f2-5342-8186-3e6c3d7eeb63"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2835-L2846"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0bcbe8c85f02735378b5be95c098ca5088f451e390ec6ce76fb732f0db297c1f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4412007ae212d12cea36ed56985bd762bd9fb54a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HETCO ApS" and pe.signatures[i].serial=="4c:68:7a:00:22:c3:6f:89:e2:53:f9:1d:1f:69:54:e2")
}
