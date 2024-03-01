import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_54Cd7Ae1C27F1421136Ed25088F4979A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2f7a0a34-6650-59d1-acf9-5ded0317ee6f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6281-L6292"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2b94ccd7f85a2b21edaf4b28f14827b399cdb82307c20320f77eb775c05751f1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "acde047c3d7b22f87d0e6d07fe0a3b734ad5f8ac"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABBYMAJUTA LTD LIMITED" and pe.signatures[i].serial=="54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a")
}
