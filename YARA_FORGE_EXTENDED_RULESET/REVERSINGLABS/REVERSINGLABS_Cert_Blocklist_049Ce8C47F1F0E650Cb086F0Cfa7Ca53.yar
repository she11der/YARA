import "pe"

rule REVERSINGLABS_Cert_Blocklist_049Ce8C47F1F0E650Cb086F0Cfa7Ca53 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aebba591-2024-584a-bba6-9a27049cf4b8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L261-L277"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9ae4a236e1252afc1db6fae4e388a53ebde7e724cc07c213d4bfc176cf0a0096"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Select'Assistance Pro" and pe.signatures[i].serial=="04:9c:e8:c4:7f:1f:0e:65:0c:b0:86:f0:cf:a7:ca:53" and 1393804799<=pe.signatures[i].not_after)
}
