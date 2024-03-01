import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_F0E150C304De35F2E9086185581F4053 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d2a5cd5b-1e4a-5714-bff2-08f2c958cd0b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3581-L3592"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "fe3d5d57d0a98414e3e4f35248d3ebf64617c16a4119a21883c3679b06146745"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c0a448b9101f48309a8e5a67c11db09da14b54bb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rare Ideas, LLC" and pe.signatures[i].serial=="f0:e1:50:c3:04:de:35:f2:e9:08:61:85:58:1f:40:53")
}
