rule SIGNATURE_BASE_Crowdstrike_SUNSPOT_02 : artifact stellarparticle sunspot STELLARPARTICLE FILE
{
	meta:
		description = "Detects mutex names in SUNSPOT"
		author = "(c) 2021 CrowdStrike Inc."
		id = "9ecb89e6-475b-5961-8a67-136a0274e1c7"
		date = "2021-01-08"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sunspot.yar#L23-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b5a528e76108f721e0508f1a7182f00c04dc55ec9b0aaece30986828921dafcc"
		score = 75
		quality = 85
		tags = "STELLARPARTICLE, FILE"
		version = "202101081448"
		actor = "StellarParticle"
		malware_family = "SUNSPOT"

	strings:
		$mutex_01 = "{12d61a41-4b74-7610-a4d8-3028d2f56395}" wide ascii
		$mutex_02 = "{56331e4d-76a3-0390-a7ee-567adf5836b7}" wide ascii

	condition:
		any of them and filesize <10MB
}
