import "pe"

rule REVERSINGLABS_Cert_Blocklist_566Ac16A57B132D3F64Dced14De790Ee : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cb2ebbd5-5036-52f6-a064-11609f02309f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4480-L4496"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "48f4d334614f6c413907d51f4d6312554b13c4f5a3c03070ceba48baa13a8247"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unirad LLC" and pe.signatures[i].serial=="56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee" and 1562889600<=pe.signatures[i].not_after)
}
