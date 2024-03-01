import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C667Ffe3A5B0A5Ae7Cf3A9E41682E91B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "509dcc22-1202-5b6e-a602-6b06c282b28d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6609-L6623"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6d3d0cfb42758f917b003f7979f7123c1789c9e9b4e01b1aebf265a298eac08f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6b66ba34ff01e0dab6e68ba244d991578a69c4ad"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and (pe.signatures[i].serial=="c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b" or pe.signatures[i].serial=="00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b"))
}
