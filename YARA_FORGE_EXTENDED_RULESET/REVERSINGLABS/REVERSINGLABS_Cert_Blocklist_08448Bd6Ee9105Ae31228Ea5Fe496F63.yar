import "pe"

rule REVERSINGLABS_Cert_Blocklist_08448Bd6Ee9105Ae31228Ea5Fe496F63 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "489ffe25-43cf-55b6-b249-17d251b9774e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2266-L2282"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9bc044b4fdf381274a2c31bc997dcdfd553595d92de7b33dc472353a00011711"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Raffaele Carnacina" and pe.signatures[i].serial=="08:44:8b:d6:ee:91:05:ae:31:22:8e:a5:fe:49:6f:63" and 1445212799<=pe.signatures[i].not_after)
}
