import "pe"

rule SIGNATURE_BASE_Sig_238_Concon
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file concon.com"
		author = "Florian Roth (Nextron Systems)"
		id = "ca7862cc-1053-5fce-a569-6ecc069314df"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2343-L2356"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
		logic_hash = "c45955cc59970657f8787ddc0e549939d2fa30d11cfd19fd12cd9067abb3bcd6"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii

	condition:
		all of them
}
