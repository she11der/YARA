import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_53E1F226Cb77574F8Fbeb5682Da091Bb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6967042e-156b-541d-970c-491dece12f08"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8236-L8249"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "41f4902e9d02254efdfd19a73de16e1128b15d264c3ed128d5ec28bd92f2d8a4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d247ec7e224a24683da3f138112ffc9607f83c917d6c45494dd744d732249260"
		reason = "SystemBC"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OdyLab Inc" and pe.signatures[i].serial=="53:e1:f2:26:cb:77:57:4f:8f:be:b5:68:2d:a0:91:bb")
}
