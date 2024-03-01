import "pe"

rule REVERSINGLABS_Cert_Blocklist_60497070Ff4A83Bc87Bdea24Da5B431D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "510ab702-103b-5863-ac9a-46a917879e72"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15170-L15186"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "30998e3f5299a37cdee83b1232249b84dbb3c154ef99237da5ce1b16f9db5da3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="60:49:70:70:ff:4a:83:bc:87:bd:ea:24:da:5b:43:1d" and 1477008000<=pe.signatures[i].not_after)
}
