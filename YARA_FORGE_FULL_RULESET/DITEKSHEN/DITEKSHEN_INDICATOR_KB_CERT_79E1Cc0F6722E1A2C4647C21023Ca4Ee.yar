import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_79E1Cc0F6722E1A2C4647C21023Ca4Ee : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0abbd882-0224-5c94-98b2-870853344883"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2887-L2898"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9d0c02ae3eab7f7c28dba04cd08fdddef2be64a1622d7fb519a4bf3a40ef19b1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "41d2f4f810a6edf42b3717cf01d4975476f63cba"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPAGETTI LTD" and pe.signatures[i].serial=="79:e1:cc:0f:67:22:e1:a2:c4:64:7c:21:02:3c:a4:ee")
}
