import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_62165B335C13A1A847Ce9Acff2B29368 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "62cd9a29-023d-5ff4-89cf-a2e74ec66ac4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6336-L6347"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "19e189c49f435f8b2aca0944d0f648a4126f83b7498982a262230e2f69ada8b7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c4cfd244d5148c5b03cac093d49af723252b643c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "t55555Prh" and pe.signatures[i].serial=="62:16:5b:33:5c:13:a1:a8:47:ce:9a:cf:f2:b2:93:68")
}
