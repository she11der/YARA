rule SIGNATURE_BASE_Woolengoldfish_Sample_1
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth (Nextron Systems)"
		id = "923de51a-8422-5318-95f5-79613d2d642e"
		date = "2015-03-25"
		modified = "2023-12-05"
		reference = "http://goo.gl/NpJpVZ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_woolengoldfish.yar#L13-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
		logic_hash = "9490715a2fc7d3c742771a8211bcfb4c0a0bafba4d5de8eee5825fdabaded6af"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Cannot execute (%d)" fullword ascii
		$s16 = "SvcName" fullword ascii

	condition:
		all of them
}
