import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6B6739E55F3F25B147C4A6767De41F57 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ee84787b-cc90-545d-8e15-bf84676f222c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5379-L5391"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		hash = "da0921c1e416b3734272dfa619f88c8cd32e9816cdcbeeb81d9e2b2e8a95af4c"
		logic_hash = "9d1a20f3dfa6c31ed557e531f7a57c64032e518c033993234849882ef769fcbd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "07a09d3d3c05918519d6f357fe7eed5e1d529f22"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Avast Antivirus SEC" and pe.signatures[i].serial=="6b:67:39:e5:5f:3f:25:b1:47:c4:a6:76:7d:e4:1f:57")
}
