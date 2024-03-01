import "pe"

rule REVERSINGLABS_Cert_Blocklist_3E267B5D14Cdf1F645C1Ec545Cec3Aee : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "adff6ae2-076c-5c97-9fea-f95d770a3821"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6694-L6710"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e36ae57d715a71aa7d26dd003d647dfa7ab16d64e5411b6c49831544fc482645"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO KBI" and pe.signatures[i].serial=="3e:26:7b:5d:14:cd:f1:f6:45:c1:ec:54:5c:ec:3a:ee" and 1579825892<=pe.signatures[i].not_after)
}
