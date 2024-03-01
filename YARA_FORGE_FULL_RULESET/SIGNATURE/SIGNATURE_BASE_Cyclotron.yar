rule SIGNATURE_BASE_Cyclotron : FILE
{
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "7099462b-2a72-56cd-8a50-27cd445eb9d2"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1735-L1752"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
		logic_hash = "f3a0edf54039479c9f4e46b20249465bbe1bca57f47afeba37965e6e3fc0127f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Device\\IDTProt" wide
		$s2 = "IoDeleteSymbolicLink" fullword ascii
		$s3 = "\\??\\slIDTProt" wide
		$s4 = "IoDeleteDevice" fullword ascii
		$s5 = "IoCreateSymbolicLink" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3KB and all of them
}
