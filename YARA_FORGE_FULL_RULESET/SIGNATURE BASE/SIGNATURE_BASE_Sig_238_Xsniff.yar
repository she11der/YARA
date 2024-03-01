import "pe"

rule SIGNATURE_BASE_Sig_238_Xsniff
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file xsniff.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1e61a732-8691-5f84-beb0-c9f7e6d46538"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2692-L2713"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
		logic_hash = "90c08db197a00885ffc62967bd814479a438f500316cf65e81fcec617517dd9c"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s3 = "%s - simple sniffer for win2000" fullword ascii
		$s4 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s5 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s7 = "http://www.xfocus.org" fullword ascii
		$s9 = "  -pass        : Filter username/password" fullword ascii
		$s18 = "  -udp         : Output udp packets" fullword ascii
		$s19 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s20 = "  -tcp         : Output tcp packets" fullword ascii

	condition:
		6 of them
}
