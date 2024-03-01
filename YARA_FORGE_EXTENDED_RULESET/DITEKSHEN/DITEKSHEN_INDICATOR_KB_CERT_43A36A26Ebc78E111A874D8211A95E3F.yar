import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_43A36A26Ebc78E111A874D8211A95E3F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "651ca649-c707-59d2-b482-5ca6d1e569b0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3750-L3761"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2588c91e1cce7e595e4237843b03f3e65427b4c3ea634e9a4f8249e9c9f49dbe"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a346bda33b5b3bea04b299fe87c165c4f221645a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Efacefcafeabbdcbcea" and pe.signatures[i].serial=="43:a3:6a:26:eb:c7:8e:11:1a:87:4d:82:11:a9:5e:3f")
}
