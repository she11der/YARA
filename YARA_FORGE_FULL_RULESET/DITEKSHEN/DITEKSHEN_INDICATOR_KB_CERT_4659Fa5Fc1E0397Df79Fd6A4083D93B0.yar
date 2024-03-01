import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4659Fa5Fc1E0397Df79Fd6A4083D93B0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a0d2449c-c1b0-5e6a-9fa3-d8fe8e318c62"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7846-L7859"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6d8a10d77e63d2a62ce45606dd9a317220aa124a50fa95028a45d9f5899ec6e3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "fa5f2dbe813b0270b1f9e53da1be024fb495e8b1848bb3c9c7392a40c8f7e8e6"
		reason = "RedLineStealer"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Incuber Services LLP" and pe.signatures[i].serial=="46:59:fa:5f:c1:e0:39:7d:f7:9f:d6:a4:08:3d:93:b0")
}
