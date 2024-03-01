import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_283518F1940A11Caf187646D8063D61D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "cf5f7f11-3af6-577b-9a5e-eafe2de34e2b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3451-L3462"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7db16bc44059e2538eb896011598a599c6aead90fb873c530ce8f5391e440164"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "aaeb19203b71e26c857613a5a2ba298c79910f5d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eeeeeeba" and pe.signatures[i].serial=="28:35:18:f1:94:0a:11:ca:f1:87:64:6d:80:63:d6:1d")
}
