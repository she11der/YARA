import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4697C7Ddd3E37Fe275Fdc6961A9093E3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9d611fee-cf29-523e-86f7-5c67f0e563a9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6773-L6785"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b3de1a753ac7a2f43ae64ee54fc81d92f70c32d4a04398a6dfc9a6ec856d8300"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ef24ae3635929c371d1427901082be9f76e58d9a"
		hash1 = "fb3f622cf5557364a0a3abacc3e9acf399b3631bf3630acb8132514c486751e7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xC3\\x89tienne Hill" and pe.signatures[i].serial=="46:97:c7:dd:d3:e3:7f:e2:75:fd:c6:96:1a:90:93:e3")
}
