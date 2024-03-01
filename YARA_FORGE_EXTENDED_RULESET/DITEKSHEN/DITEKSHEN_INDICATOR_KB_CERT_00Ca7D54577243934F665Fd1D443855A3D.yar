import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ca7D54577243934F665Fd1D443855A3D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8519119d-a37b-5438-a642-48e1d40024b8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2183-L2194"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "867844464609a043902f07aad3fa568b482259655bc181d992bd409437165790"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2ea2c7625c1a42fff63f0b17cfc4fd0c0f76d7eb45a86b18ec9a630d3d8ad913"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FABO SP Z O O" and pe.signatures[i].serial=="00:ca:7d:54:57:72:43:93:4f:66:5f:d1:d4:43:85:5a:3d")
}
