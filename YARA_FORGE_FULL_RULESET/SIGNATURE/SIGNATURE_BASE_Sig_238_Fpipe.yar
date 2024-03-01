import "pe"

rule SIGNATURE_BASE_Sig_238_Fpipe
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0b2f11d9-a919-5790-8724-d2f028e4fa3a"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2323-L2341"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
		logic_hash = "ecf143c231aeb37cf9575c3ea8db83c9a049e85a7c95668deeac0878f9c30b9c"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s3 = " -s    - outbound source port number" fullword ascii
		$s5 = "http://www.foundstone.com" fullword ascii
		$s20 = "Attempting to connect to %s port %d" fullword ascii

	condition:
		all of them
}
