import "pe"

rule SIGNATURE_BASE_Linuxhacktool_Eyes_Scanssh
{
	meta:
		description = "Linux hack tools - file scanssh"
		author = "Florian Roth (Nextron Systems)"
		id = "9546d0d8-42af-5b4c-ac93-195d14bfbb5b"
		date = "2015-01-19"
		modified = "2023-12-05"
		reference = "not set"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2822-L2847"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "467398a6994e2c1a66a3d39859cde41f090623ad"
		logic_hash = "cb20c28f1767ce23f60c377943d8a129fa069b1a1407bbaf43370f0ff79ade30"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Connection closed by remote host" fullword ascii
		$s1 = "Writing packet : error on socket (or connection closed): %s" fullword ascii
		$s2 = "Remote connection closed by signal SIG%s %s" fullword ascii
		$s4 = "Reading private key %s failed (bad passphrase ?)" fullword ascii
		$s5 = "Server closed connection" fullword ascii
		$s6 = "%s: line %d: list delimiter not followed by keyword" fullword ascii
		$s8 = "checking for version `%s' in file %s required by file %s" fullword ascii
		$s9 = "Remote host closed connection" fullword ascii
		$s10 = "%s: line %d: bad command `%s'" fullword ascii
		$s13 = "verifying that server is a known host : file %s not found" fullword ascii
		$s14 = "%s: line %d: expected service, found `%s'" fullword ascii
		$s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii
		$s17 = "Public key from server (%s) doesn't match user preference (%s)" fullword ascii

	condition:
		all of them
}
