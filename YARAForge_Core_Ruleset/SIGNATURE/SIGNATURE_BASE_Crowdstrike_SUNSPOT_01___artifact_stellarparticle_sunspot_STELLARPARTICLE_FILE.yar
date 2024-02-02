rule SIGNATURE_BASE_Crowdstrike_SUNSPOT_01___artifact_stellarparticle_sunspot_STELLARPARTICLE_FILE
{
	meta:
		description = "Detects RC4 and AES key encryption material in SUNSPOT"
		author = "(c) 2021 CrowdStrike Inc."
		id = "2a2a5cfc-d059-5942-bd70-c3169e9ceb45"
		date = "2021-01-08"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_sunspot.yar#L1-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "660e955c22a9f02e952677f7a38da04e2ec369a1f68658bc261063e830dea180"
		score = 75
		quality = 85
		tags = "STELLARPARTICLE, FILE"
		version = "202101081448"
		actor = "StellarParticle"
		malware_family = "SUNSPOT"

	strings:
		$key = {fc f3 2a 83 e5 f6 d0 24 a6 bf ce 88 30 c2 48 e7}
		$iv = {81 8c 85 49 b9 00 06 78 0b e9 63 60 26 64 b2 da}

	condition:
		all of them and filesize <32MB
}