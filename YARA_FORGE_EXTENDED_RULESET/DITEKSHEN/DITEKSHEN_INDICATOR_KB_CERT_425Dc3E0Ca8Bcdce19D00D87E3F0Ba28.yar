import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_425Dc3E0Ca8Bcdce19D00D87E3F0Ba28 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "41423db4-c475-558b-9a27-2b0ea59102ad"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7558-L7569"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0fc85d3d01b37ff7870cade6f8e0e756593ff0b5c9eea3b687ff52985caa20dd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c58bc4370fa01d9a7772fa8c0e7c4c6c99b90561"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Protover LLC" and pe.signatures[i].serial=="42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28")
}
