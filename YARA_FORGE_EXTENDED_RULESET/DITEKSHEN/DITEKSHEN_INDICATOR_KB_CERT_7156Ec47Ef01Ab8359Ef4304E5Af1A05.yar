import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7156Ec47Ef01Ab8359Ef4304E5Af1A05 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f77ccdb6-77b6-5c47-bde6-2b1b449f9533"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1533-L1544"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "fc8073ebb9847d642f15cc74859b643afe00b3c331f68c06f3ff62c037225201"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "59fe580974e2f813c2a00b4be01acd46c94fdea89a3049433cd5ba5a2d96666d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BOREC, OOO" and pe.signatures[i].serial=="71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05")
}
