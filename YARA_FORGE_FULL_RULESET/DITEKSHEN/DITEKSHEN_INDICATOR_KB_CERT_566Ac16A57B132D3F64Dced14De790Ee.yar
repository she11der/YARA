import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_566Ac16A57B132D3F64Dced14De790Ee : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "05f49d36-7bf1-5bbc-b728-e1616366c15e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1858-L1869"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0618ce3ce0c5f8923c12a99586bbec8ec86229c7e08af75f5b0756f348d53bd5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2e44464a5907ac46981bebd8eed86d8deec9a4cfafdf1652c8ba68551d4443ff"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unirad LLC" and pe.signatures[i].serial=="56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee")
}
