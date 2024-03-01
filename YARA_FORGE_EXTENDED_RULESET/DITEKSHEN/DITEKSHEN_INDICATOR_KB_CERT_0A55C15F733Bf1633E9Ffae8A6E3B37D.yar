import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A55C15F733Bf1633E9Ffae8A6E3B37D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "86d8453b-115d-59f8-8123-5aff071ec3dd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3516-L3527"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a772edb12dc0c351bb4d11f3e6ab3d9705af156ebeb4b8fff281bb418bfa1764"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "591f68885fc805a10996262c93aab498c81f3010"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Osnova OOO" and pe.signatures[i].serial=="0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d")
}
