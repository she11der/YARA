import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_029Bf7E1Cb09Fe277564Bd27C267De5A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "19d1012f-9a9e-5d84-885c-2571bfd1876c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8866-L8879"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a8c817dc99d55dcbea31334cc10b6a7ae3b5cf831e28cb2daf9d4b06fb4bec60"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2b18684a4b1348bf78f6d58d3397ee5ca80610d1c39b243c844e08f1c1e0b4bf"
		reason = "Lazarus"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAMOYAJ LIMITED" and pe.signatures[i].serial=="02:9b:f7:e1:cb:09:fe:27:75:64:bd:27:c2:67:de:5a")
}
