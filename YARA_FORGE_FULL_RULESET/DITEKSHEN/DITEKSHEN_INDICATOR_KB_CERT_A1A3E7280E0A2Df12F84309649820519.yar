import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_A1A3E7280E0A2Df12F84309649820519 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "71ad82d6-e45e-52a9-b1ff-f00cfe7b5186"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3594-L3605"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5c656fa5a6671f717cda5433c8780d308f11b7937e5ff66b4f3f74623b217365"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "33d254c711937b469d1b08ef15b0a9f5b4d27250"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nir Sofer" and pe.signatures[i].serial=="a1:a3:e7:28:0e:0a:2d:f1:2f:84:30:96:49:82:05:19")
}
