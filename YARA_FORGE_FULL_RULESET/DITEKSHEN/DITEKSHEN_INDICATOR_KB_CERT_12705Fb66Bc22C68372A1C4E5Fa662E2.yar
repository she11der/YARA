import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_12705Fb66Bc22C68372A1C4E5Fa662E2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c9604f76-ad8a-5ac0-ba12-5030b12bedbf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7601-L7613"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a212e491ce661dec5512f82eed42b1863afb75ce7fb185c41af178f3852b78c8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "288959bd1e8dd12f773e9601dc21c57678769909"
		hash1 = "151b1495d6d1c68e32cdba36d6d3e1d40c8c0d3c12e9e5bd566f1ee742b81b4e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APRIL BROTHERS LTD" and pe.signatures[i].serial=="12:70:5f:b6:6b:c2:2c:68:37:2a:1c:4e:5f:a6:62:e2")
}
