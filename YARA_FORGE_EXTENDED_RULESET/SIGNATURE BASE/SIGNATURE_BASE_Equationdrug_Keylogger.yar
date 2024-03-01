rule SIGNATURE_BASE_Equationdrug_Keylogger
{
	meta:
		description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "57b6af34-577b-58ec-9a9e-91911c32270b"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L494-L509"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"
		logic_hash = "b5db0e6e24979b07cd180fed11545daef281e7b0858a7de001a83c2cbc186557"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" wide
		$s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
		$s3 = "\\DosDevices\\Gk" wide
		$s5 = "\\Device\\Gk0" wide

	condition:
		all of them
}
