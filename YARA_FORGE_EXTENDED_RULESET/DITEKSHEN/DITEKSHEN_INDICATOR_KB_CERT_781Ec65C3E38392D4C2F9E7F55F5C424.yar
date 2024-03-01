import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_781Ec65C3E38392D4C2F9E7F55F5C424 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d056fb18-e641-50bb-af86-ea124203f16c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3191-L3202"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "00b01a874e29fd2e25200f5e50c7121c3cc4bca614c31dd149d6197088292b35"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5d20e8f899c7e48a0269c2b504607632ba833e40"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Facacafbfddbdbfad" and pe.signatures[i].serial=="78:1e:c6:5c:3e:38:39:2d:4c:2f:9e:7f:55:f5:c4:24")
}
