import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5Fbf16A33D26390A15F046C310030Cf0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6c010106-141d-5121-9594-73edc872a381"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7459-L7471"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "fc68fe14ec70de74a6dae7891dfbb82ee7974f37469cfa72d735e70e9194c405"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "61f422db86bbc5093b1466a281f13346f8d81792"
		hash1 = "f45e5f160a6de454d1db21b599843637103506545183a30053d03b609f92bbdc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MACHINES SATU MARE SRL" and pe.signatures[i].serial=="5f:bf:16:a3:3d:26:39:0a:15:f0:46:c3:10:03:0c:f0")
}
