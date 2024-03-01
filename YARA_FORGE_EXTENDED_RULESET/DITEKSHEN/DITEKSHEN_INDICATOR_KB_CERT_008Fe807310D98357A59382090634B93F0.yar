import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008Fe807310D98357A59382090634B93F0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bf4326b3-a838-5dff-a6e1-ac71c6fb871d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5539-L5550"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a90430a6f07f67ead37e5cba9f0baee92551511a9f33a2a1fd3d2419322aaa8b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "acd6cf38d03c355ddb84b96a7365bfc1738a0ec5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MAVE MEDIA" and pe.signatures[i].serial=="00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0")
}
