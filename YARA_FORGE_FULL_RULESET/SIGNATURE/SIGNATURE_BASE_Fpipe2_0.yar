import "pe"

rule SIGNATURE_BASE_Fpipe2_0
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7e104cf6-69d2-590e-8999-4f0d448719f2"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2535-L2553"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "891609db7a6787575641154e7aab7757e74d837b"
		logic_hash = "b28566315ddda7765dfee722f5ad02c1206c6916363d86407fdc61b53148f511"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = " -s    - outbound connection source port number" fullword ascii
		$s3 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s4 = "http://www.foundstone.com" fullword ascii
		$s19 = "FPipe" fullword ascii

	condition:
		all of them
}
