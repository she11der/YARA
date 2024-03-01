import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0F007898Afcba5F8Af8Ae65D01803617 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1c3fddc2-3348-5f94-bf3e-5ce95b6ef009"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7515-L7527"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "260dbdd3d295ace9c478cc27061065803c159957a1eb2f7965ee2b358f02a73c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5687481a453414e63e76e1135ed53f4bd0410b05"
		hash1 = "815f1f87e2df79e3078c63b3cb1ffb7d17fd24f6c7092b8bbe1f5f8ceda5df22"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TechnoElek s.r.o." and pe.signatures[i].serial=="0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17")
}
