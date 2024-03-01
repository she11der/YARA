import "pe"

rule SIGNATURE_BASE_Ncat_Hacktools_CN
{
	meta:
		description = "Disclosed hacktool set - file nc.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bdbfaf75-f8c0-508e-b6b1-9ddea179a325"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1067-L1085"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "001c0c01c96fa56216159f83f6f298755366e528"
		logic_hash = "0e059e90447747ed5259da4a870036d37d181c1cfea734ab25e760e81612f0f3"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
		$s3 = "gethostpoop fuxored" fullword ascii
		$s6 = "VERNOTSUPPORTED" fullword ascii
		$s7 = "%s [%s] %d (%s)" fullword ascii
		$s12 = " `--%s' doesn't allow an argument" fullword ascii

	condition:
		all of them
}
