import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_02C5351936Abe405Ac760228A40387E8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "32e200c3-678f-5be4-b55b-2a7a32e56843"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L458-L469"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ae9e428c5e7c1ab67be291da93e6d3fa694e3a9b347672817cbf1cac44837a04"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1174c2affb0a364c1b7a231168cfdda5989c04c5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RESURS-RM OOO" and pe.signatures[i].serial=="02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8")
}
