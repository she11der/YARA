import "pe"

rule SIGNATURE_BASE_Chinese_Hacktool_1014
{
	meta:
		description = "Detects a chinese hacktool with unknown use"
		author = "Florian Roth (Nextron Systems)"
		id = "e5db5f58-a1fd-51e0-9037-337fcca71f11"
		date = "2014-10-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L585-L602"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "98c07a62f7f0842bcdbf941170f34990"
		logic_hash = "ffb1f653fd536a46dae4bf2c91c3c0582b703b8f0d33838b9736083e307a8e79"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
		$s1 = "msctls_progress32" fullword wide
		$s2 = "Reply-To: %s" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "html htm htx asp" fullword ascii

	condition:
		all of them
}
