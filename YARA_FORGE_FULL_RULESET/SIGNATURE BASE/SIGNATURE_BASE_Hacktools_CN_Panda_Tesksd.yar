import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Panda_Tesksd
{
	meta:
		description = "Disclosed hacktool set - file tesksd.jpg"
		author = "Florian Roth (Nextron Systems)"
		id = "399ff307-c2e8-57bb-b792-a2c599e8686e"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1323-L1338"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
		logic_hash = "dc81acef0ad3e6307f68ee755e5b27f2dcf1e2822e560a72dc5ae572703f4459"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
		$s1 = "ExeMiniDownload.exe" fullword wide
		$s16 = "POST %Hs" fullword ascii

	condition:
		all of them
}
