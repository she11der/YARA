import "pe"

rule SIGNATURE_BASE_Linuxhacktool_Eyes_Pscan2
{
	meta:
		description = "Linux hack tools - file pscan2"
		author = "Florian Roth (Nextron Systems)"
		id = "02d96766-6696-5410-ad48-bd8cb642ac51"
		date = "2015-01-19"
		modified = "2023-12-05"
		reference = "not set"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2849-L2867"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "56b476cba702a4423a2d805a412cae8ef4330905"
		logic_hash = "3686ccbd53a6dcedf9b10d131a1fc76b51b265328ad10f63671b64d4bf57a0b6"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
		$s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
		$s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
		$s8 = "Invalid IP." fullword ascii
		$s9 = "# scanning: " fullword ascii
		$s10 = "Unable to allocate socket." fullword ascii

	condition:
		2 of them
}
