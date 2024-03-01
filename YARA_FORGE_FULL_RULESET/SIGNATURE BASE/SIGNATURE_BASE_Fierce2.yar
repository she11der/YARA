import "pe"

rule SIGNATURE_BASE_Fierce2
{
	meta:
		description = "This signature detects the Fierce2 domain scanner"
		author = "Florian Roth (Nextron Systems)"
		id = "08a72151-48c2-513b-995f-be0d5acba7dd"
		date = "2014-01-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L126-L139"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "05502827dd5d1903507fd1e176d518516a5c1965fb4e51ea26b1a05eb0dce3d2"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"

	condition:
		1 of them
}
