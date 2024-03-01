import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ef9D0Cf071D463Cd63D13083046A7B8D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f4b83bdf-ce07-5bad-b3e2-2c192d67f9f1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5309-L5320"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9cf4ee1b3000d96d419bfd3e9ac3fb07f843aed735582c72e3a9799e2a56e364"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "346849dfdeb9bb1a97d98c62d70c578dacbcf30c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rubin LLC" and pe.signatures[i].serial=="00:ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d")
}
