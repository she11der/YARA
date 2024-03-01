import "pe"

rule REVERSINGLABS_Cert_Blocklist_112613B7B5F696Cf377680F6463Fcc8C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c0015521-b163-51ab-8c27-da3b1a8df084"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4442-L4458"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "50fd35617e059a5fe9d9e0fdb4b880c20e406357bbb2d037f9e6e9db47b8e49f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Infoware Cloud Limited" and pe.signatures[i].serial=="11:26:13:b7:b5:f6:96:cf:37:76:80:f6:46:3f:cc:8c" and 1566518400<=pe.signatures[i].not_after)
}
