import "pe"

rule REVERSINGLABS_Cert_Blocklist_35B49Ee870Aea532E6Ef0A4987105C8F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "88dedb69-52f4-59d3-b397-6a091a866cc5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12518-L12534"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a9d8e9db453f40e32a0cb6412db8885db54053fdf3d7908b884361a493f97b1f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kancelaria Adwokacka Adwokat Aleksandra Krzemi\\xC5\\x84ska" and pe.signatures[i].serial=="35:b4:9e:e8:70:ae:a5:32:e6:ef:0a:49:87:10:5c:8f" and 1663151018<=pe.signatures[i].not_after)
}
