import "pe"

rule SIGNATURE_BASE_Fscan_Portscanner : FILE
{
	meta:
		description = "Fscan port scanner scan output / strings"
		author = "Florian Roth (Nextron Systems)"
		id = "400383dc-8bc0-5e77-a3f3-d6ba9f4c3c0f"
		date = "2017-01-06"
		modified = "2023-12-05"
		reference = "https://twitter.com/JamesHabben/status/817112447970480128"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3447-L3461"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "35770f040da0b14fe4492a44383e332c9912bd89943838627491196ce8f0ec37"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Time taken:" fullword ascii
		$s2 = "Scan finished at" fullword ascii
		$s3 = "Scan started at" fullword ascii

	condition:
		filesize <20KB and 3 of them
}
