import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_010000000001302693Cb45 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0ab8e30d-dd75-5dd1-9bc8-413e59d5d310"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4535-L4547"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		hash = "74069d20e8b8299590420c9af2fdc8856c14d94929c285948585fc89ab2f938f"
		logic_hash = "74c5d88012ab3e975123cde51ae3d01b6bee1ad0d6c0f5492c507fb2472b7532"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bc5fcb5a2b5e0609e2609cff5e272330f79b2375"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AutoIt Consulting Ltd" and pe.signatures[i].serial=="01:00:00:00:00:01:30:26:93:cb:45")
}
